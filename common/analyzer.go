package common

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/olekukonko/tablewriter"
)

type Analyzer2Opts struct {
	Transactions map[string]*TxSummaryEntry
	Sourelog     map[string]map[string]int64 // [hash][source] = timestampMs
	SourceComps  []SourceComp
}

type Analyzer2 struct {
	Transactions map[string]*TxSummaryEntry
	Sourelog     map[string]map[string]int64
	SourceComps  []SourceComp

	nTransactionsPerSource map[string]int64
	sources                []string

	nUniqueTransactions int64
	nIncluded           int64
	nNotIncluded        int64

	txTypes              []int64
	nTransactionsPerType map[int64]int64
	txBytesPerType       map[int64]int64

	// landed vs non-landed transactions
	nTxOnChainBySource    map[string]int64
	nTxNotOnChainBySource map[string]int64

	nTxExclusiveIncluded map[string]map[bool]int64 // [src][wasIncluded]count
	nExclusiveOrderflow  int64

	nTxExclusiveIncludedCnt    int64
	nTxExclusiveNotIncludedCnt int64

	timestampFirst int64
	timestampLast  int64
	timeFirst      time.Time
	timeLast       time.Time
	duration       time.Duration
}

func NewAnalyzer2(opts Analyzer2Opts) *Analyzer2 {
	a := &Analyzer2{ //nolint:exhaustruct
		Transactions: make(map[string]*TxSummaryEntry),
		Sourelog:     opts.Sourelog,
		SourceComps:  opts.SourceComps,

		nTransactionsPerSource: make(map[string]int64),
		nTxOnChainBySource:     make(map[string]int64),
		nTxNotOnChainBySource:  make(map[string]int64),
		nTxExclusiveIncluded:   make(map[string]map[bool]int64), // [source][isIncluded]count
		nTransactionsPerType:   make(map[int64]int64),
		txBytesPerType:         make(map[int64]int64),
	}

	// Now add all transactions to analyzer cache that were not included before received
	for _, tx := range opts.Transactions {
		if tx.WasIncludedBeforeReceived() {
			continue
		}

		a.Transactions[strings.ToLower(tx.Hash)] = tx
	}

	// Run the analyzer
	a.init()
	return a
}

// Init does some efficient initial data analysis and preparation for later use
func (a *Analyzer2) init() {
	a.nUniqueTransactions = int64(len(a.Transactions))

	// iterate over tx to
	for _, tx := range a.Transactions {
		if tx.IncludedAtBlockHeight == 0 {
			a.nNotIncluded += 1
		} else {
			a.nIncluded += 1
		}

		// Count transactions per type
		a.nTransactionsPerType[tx.TxType] += 1
		a.txBytesPerType[tx.TxType] += int64(len(tx.RawTx)) / 2

		// Go over sources
		for _, src := range tx.Sources {
			// Count overall tx / source
			a.nTransactionsPerSource[src] += 1

			// Count landed vs non-landed tx
			if tx.IncludedAtBlockHeight == 0 {
				a.nTxNotOnChainBySource[src] += 1
			} else {
				a.nTxOnChainBySource[src] += 1
			}

			// Count exclusive orderflow
			if len(tx.Sources) == 1 {
				if a.nTxExclusiveIncluded[src] == nil {
					a.nTxExclusiveIncluded[src] = make(map[bool]int64)
				}
				a.nTxExclusiveIncluded[src][tx.IncludedAtBlockHeight != 0] += 1
				a.nExclusiveOrderflow += 1

				if tx.IncludedAtBlockHeight == 0 {
					a.nTxExclusiveNotIncludedCnt += 1
				} else {
					a.nTxExclusiveIncludedCnt += 1
				}
			}
		}

		// find first and last timestamp
		if a.timestampFirst == 0 || tx.Timestamp < a.timestampFirst {
			a.timestampFirst = tx.Timestamp
		}
		if a.timestampLast == 0 || tx.Timestamp > a.timestampLast {
			a.timestampLast = tx.Timestamp
		}
	}

	// convert timestamps to duration and UTC time
	a.timeFirst = time.Unix(a.timestampFirst/1000, 0).UTC()
	a.timeLast = time.Unix(a.timestampLast/1000, 0).UTC()
	a.duration = a.timeLast.Sub(a.timeFirst)

	// get sorted list of sources
	for src := range a.nTransactionsPerSource {
		a.sources = append(a.sources, src)
	}
	sort.Strings(a.sources)

	// get sorted list of txTypes
	for txType := range a.nTransactionsPerType {
		a.txTypes = append(a.txTypes, txType)
	}
	sort.Slice(a.txTypes, func(i, j int) bool { return a.txTypes[i] < a.txTypes[j] })
}

// latencyComp returns arrays of latency differences for the node that was faster
func (a *Analyzer2) latencyComp(src, ref string) (srcH, refH *hdrhistogram.Histogram, totalSeenByBoth int) {
	srcH = hdrhistogram.New(1, 5000000, 3)
	refH = hdrhistogram.New(1, 5000000, 3)

	// 1. Find all txs that were seen by both source and reference and were included on-chain
	txHashes := make(map[string]map[string]int64) // [txHash][source] = timestampMs
	for txHash, tx := range a.Transactions {
		txHashLower := strings.ToLower(txHash)
		if len(tx.Sources) == 1 {
			continue
		}

		// Only count transactions included on-chain
		if tx.IncludedAtBlockHeight == 0 {
			continue
		}

		// ensure tx was seen by both source and reference
		if !tx.HasSource(src) || !tx.HasSource(ref) {
			continue
		}

		txHashes[txHashLower] = make(map[string]int64)
	}

	// 2. Iterate over sourcelog and find the first timestamp for each source
	for txHash, sources := range a.Sourelog {
		txHashLower := strings.ToLower(txHash)
		if _, ok := txHashes[txHashLower]; !ok {
			continue
		}

		_, seenBySrc := sources[src]
		_, seenByRef := sources[ref]
		if !seenBySrc || !seenByRef {
			continue
		}

		// Set the lowest timestamp for each source
		if txHashes[txHashLower][src] == 0 || sources[src] < txHashes[txHashLower][src] {
			txHashes[txHashLower][src] = sources[src]
		}
		if txHashes[txHashLower][ref] == 0 || sources[ref] < txHashes[txHashLower][ref] {
			txHashes[txHashLower][ref] = sources[ref]
		}
	}

	// 3. For each mutual transaction, add latency difference to histogram
	for _, sources := range txHashes {
		srcTS := sources[src]
		localTS := sources[ref]
		diff := localTS - srcTS

		if diff == 0 {
			// equal, do nothing
		} else if diff > 0 {
			srcH.RecordValue(diff) //nolint:errcheck
		} else {
			refH.RecordValue(-diff) //nolint:errcheck
		}
	}

	return srcH, refH, len(txHashes)
}

func (a *Analyzer2) Print() {
	fmt.Println(a.Sprint())
}

func (a *Analyzer2) Sprint() string {
	out := fmt.Sprintln("[Mempool Dumpster](https://mempool-dumpster.flashbots.net)")
	out += fmt.Sprintln("==========================================================")
	out += fmt.Sprintln("")

	_dateStr := FmtDateDay(a.timeFirst)
	_dayLast := FmtDateDay(a.timeLast)
	if _dateStr != _dayLast {
		_dateStr += " - " + _dayLast
	}

	out += fmt.Sprintf("Date: %s \n", _dateStr)
	out += fmt.Sprintln("")
	out += fmt.Sprintf("- From: %s UTC \n", FmtDateDayTime(a.timeFirst))
	out += fmt.Sprintf("- To:   %s UTC \n", FmtDateDayTime(a.timeLast))
	durStr := FmtDuration(a.duration)
	if durStr != "23h 59m 59s" {
		out += fmt.Sprintf("- (%s) \n", durStr)
	}
	out += fmt.Sprintln("")

	out += Printer.Sprintf("Unique transactions: %10d \n", a.nUniqueTransactions)
	out += fmt.Sprintln("")
	out += Printer.Sprintf("- Included on-chain: %10d (%5s) \n", a.nIncluded, Int64DiffPercentFmt(a.nIncluded, a.nUniqueTransactions, 1))
	out += Printer.Sprintf("- Not included:      %10d (%5s) \n", a.nNotIncluded, Int64DiffPercentFmt(a.nNotIncluded, a.nUniqueTransactions, 1))

	if len(a.Sourelog) == 0 {
		return out
	}

	out += fmt.Sprintln("")
	out += fmt.Sprintf("Sources: %s \n", strings.Join(TitleStrings(a.sources), ", "))
	out += fmt.Sprintln("")

	out += fmt.Sprintln("-----------------")
	out += fmt.Sprintln("Transaction Stats")
	out += fmt.Sprintln("-----------------")
	out += fmt.Sprintln("")

	// TxType count
	buff := bytes.Buffer{}
	table := tablewriter.NewWriter(&buff)
	SetupMarkdownTableWriter(table)
	table.SetHeader([]string{"Tx Type", "Count"})
	// table.SetHeader([]string{"Tx Type", "Count", "Size Total", "Size Avg"})
	for txType := range a.txTypes {
		count := a.nTransactionsPerType[int64(txType)]
		table.Append([]string{
			fmt.Sprint(txType),
			Printer.Sprintf("%10d (%5s)", count, Int64DiffPercentFmt(count, a.nUniqueTransactions, 1)),
			// HumanBytes(uint64(a.txBytesPerType[int64(txType)])),
			// HumanBytes(uint64(a.txBytesPerType[int64(txType)] / count)),
		})
	}
	table.Render()
	out += buff.String()

	// Add per-source tx stats
	out += fmt.Sprintln("")
	out += fmt.Sprintln("------------")
	out += fmt.Sprintln("Source Stats")
	out += fmt.Sprintln("------------")
	out += fmt.Sprintln("")
	buff = bytes.Buffer{}
	table = tablewriter.NewWriter(&buff)
	SetupMarkdownTableWriter(table)
	table.SetHeader([]string{"Source", "Transactions", "Included on-chain", "Not included"})
	for _, src := range a.sources {
		nTx := a.nTransactionsPerSource[src]
		nOnChain := a.nTxOnChainBySource[src]
		nNotIncluded := a.nTxNotOnChainBySource[src]

		strTx := PrettyInt64(nTx)
		strOnChain := Printer.Sprintf("%10d (%5s)", nOnChain, Int64DiffPercentFmt(nOnChain, nTx, 1))
		strNotIncluded := Printer.Sprintf("%10d (%5s)", nNotIncluded, Int64DiffPercentFmt(nNotIncluded, nTx, 1))
		row := []string{Title(src), strTx, strOnChain, strNotIncluded}
		table.Append(row)
	}
	table.Render()
	out += buff.String()

	// Exclusive orderflow
	out += fmt.Sprintln("")
	out += fmt.Sprintln("----------------------")
	out += fmt.Sprintln("Exclusive Transactions")
	out += fmt.Sprintln("----------------------")
	out += fmt.Sprintln("")

	out += Printer.Sprintf("%d of %d exclusive transactions were included on-chain (%s). \n", a.nTxExclusiveIncludedCnt, a.nExclusiveOrderflow, Int64DiffPercentFmt(a.nTxExclusiveIncludedCnt, a.nExclusiveOrderflow, 2))
	out += fmt.Sprintln("")

	buff = bytes.Buffer{}
	table = tablewriter.NewWriter(&buff)
	SetupMarkdownTableWriter(table)
	table.SetHeader([]string{"Source", "Transactions", "Included on-chain", "Not included"})

	for _, src := range a.sources {
		if a.nTxExclusiveIncluded[src] == nil {
			continue
		}

		nIncluded := a.nTxExclusiveIncluded[src][true]
		nNotIncluded := a.nTxExclusiveIncluded[src][false]
		nExclusive := nIncluded + nNotIncluded
		sExclusive := PrettyInt64(nExclusive)
		sIncluded := Printer.Sprintf("%10d (%5s)", nIncluded, Int64DiffPercentFmt(nIncluded, nExclusive, 1))
		sNotIncluded := Printer.Sprintf("%10d (%6s)", nNotIncluded, Int64DiffPercentFmt(nNotIncluded, nExclusive, 1))
		row := []string{Title(src), sExclusive, sIncluded, sNotIncluded}
		table.Append(row)
	}
	table.Render()
	out += buff.String()

	// latency analysis for various sources:
	out += fmt.Sprintln("")
	out += fmt.Sprintln("------------------")
	out += fmt.Sprintln("Latency Comparison")
	out += fmt.Sprintln("------------------")

	for _, comp := range a.SourceComps {
		buff = bytes.Buffer{}
		table = tablewriter.NewWriter(&buff)
		SetupMarkdownTableWriter(table)
		table.SetAlignment(tablewriter.ALIGN_RIGHT)
		table.SetHeader([]string{"", comp.Source + " first", comp.Reference + " first"})

		srcH, refH, totalSeenByBoth := a.latencyComp(comp.Source, comp.Reference)
		if totalSeenByBoth == 0 {
			continue
		}

		out += fmt.Sprintln("")
		out += fmt.Sprintf("### %s - %s \n\n%s shared included transactions. \n", Caser.String(comp.Source), Caser.String(comp.Reference), PrettyInt(totalSeenByBoth))
		out += fmt.Sprintln("")

		table.Append([]string{
			"count",
			Printer.Sprintf("%d", srcH.TotalCount()),
			Printer.Sprintf("%d", refH.TotalCount()),
		})
		table.Append([]string{
			"percent",
			Printer.Sprintf("%5s", Int64DiffPercentFmtC(srcH.TotalCount(), int64(totalSeenByBoth), 1, " %%")),
			Printer.Sprintf("%5s", Int64DiffPercentFmtC(refH.TotalCount(), int64(totalSeenByBoth), 1, " %%")),
		})
		table.Append([]string{"median", Printer.Sprintf("%d ms", srcH.ValueAtQuantile(50.0)), Printer.Sprintf("%d ms", refH.ValueAtQuantile(50.0))})
		table.Append([]string{"p90", Printer.Sprintf("%d ms", srcH.ValueAtQuantile(90.0)), Printer.Sprintf("%d ms", refH.ValueAtQuantile(90.0))})
		table.Append([]string{"p95", Printer.Sprintf("%d ms", srcH.ValueAtQuantile(95.0)), Printer.Sprintf("%d ms", refH.ValueAtQuantile(95.0))})
		table.Append([]string{"p99", Printer.Sprintf("%d ms", srcH.ValueAtQuantile(99.0)), Printer.Sprintf("%d ms", refH.ValueAtQuantile(99.0))})

		table.Render()
		out += buff.String()
	}

	return out
}

func (a *Analyzer2) WriteToFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	content := a.Sprint()
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	_, err = f.WriteString(content)
	return err
}
