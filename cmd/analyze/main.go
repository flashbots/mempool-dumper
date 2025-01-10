package main

import (
	"fmt"
	"os"
	"time"

	"github.com/flashbots/mempool-dumpster/common"
	"github.com/urfave/cli/v2"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/reader"
	"go.uber.org/zap"
)

var (
	version = "dev" // is set during build process
	debug   = os.Getenv("DEBUG") == "1"
	maxEnv  = common.GetEnvInt("MAX", 0)

	// Helpers
	log *zap.SugaredLogger

	// CLI flags
	cliFlags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "input-parquet",
			Usage: "input parquet files",
		},
		&cli.StringSliceFlag{
			Name:  "input-sourcelog",
			Usage: "input sourcelog files",
		},
		&cli.StringFlag{
			Name:  "out",
			Usage: "output filename",
		},
		// &cli.StringSliceFlag{
		// 	Name:  "tx-blacklist",
		// 	Usage: "metadata CSV/ZIP input files with transactions to ignore in analysis",
		// },
		// &cli.StringSliceFlag{
		// 	Name:  "tx-whitelist",
		// 	Usage: "metadata CSV/ZIP input files to only use transactions in there for analysis",
		// },
		&cli.StringSliceFlag{
			Name:  "cmp",
			Usage: "compare these sources",
		},
	}
)

func main() {
	log = common.GetLogger(debug, false)
	defer func() { _ = log.Sync() }()

	app := &cli.App{
		Name:   "analyze",
		Usage:  "Analyze transaction and sourcelog files",
		Flags:  cliFlags,
		Action: analyzeV2,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func analyzeV2(cCtx *cli.Context) error {
	outFile := cCtx.String("out")
	// ignoreTxsFiles := cCtx.StringSlice("tx-blacklist")
	// whitelistTxsFiles := cCtx.StringSlice("tx-whitelist")
	parquetInputFiles := cCtx.StringSlice("input-parquet")
	inputSourceLogFiles := cCtx.StringSlice("input-sourcelog")
	cmpSources := cCtx.StringSlice("cmp")
	sourceComps := common.DefaultSourceComparisons
	if len(cmpSources) > 0 {
		sourceComps = common.NewSourceComps(cmpSources)
	}

	if len(parquetInputFiles) == 0 {
		log.Fatal("no input-parquet files specified")
	}

	log.Infow("Analyzer V2", "version", version)
	// log.Infow("Comparing:", "sources", sourceComps)

	// Ensure output files are don't yet exist
	common.MustNotExist(log, outFile)
	log.Infof("Output file: %s", outFile)

	// Check input files
	for _, fn := range parquetInputFiles {
		common.MustBeParquetFile(log, fn)
	}
	// for _, fn := range append(ignoreTxsFiles, whitelistTxsFiles...) {
	// 	common.MustBeCSVFile(log, fn)
	// }

	// Load parquet input files
	timeStart := time.Now()
	log.Infow("Loading parquet input files...", "memUsed", common.GetMemUsageHuman())
	fr, err := local.NewLocalFileReader(parquetInputFiles[0])
	if err != nil {
		log.Fatalw("Can't open file", "error", err)
	}
	pr, err := reader.NewParquetReader(fr, new(common.TxSummaryEntry), 4)
	if err != nil {
		log.Fatalw("Can't create parquet reader", "error", err)
	}
	num := int(pr.GetNumRows())
	entries := make(map[string]*common.TxSummaryEntry)
	var i int
	for i = 0; i < num; i++ {
		stus := make([]common.TxSummaryEntry, 1)
		if err = pr.Read(&stus); err != nil {
			log.Errorw("Read error", "error", err)
		}
		if i%20_000 == 0 {
			log.Infow(common.Printer.Sprintf("- Loaded %10d / %d rows", i, num), "memUsed", common.GetMemUsageHuman())
		}
		entries[stus[0].Hash] = &stus[0]
		if i+1 == maxEnv {
			break
		}
	}
	pr.ReadStop()
	fr.Close()
	log.Infow(common.Printer.Sprintf("- Loaded %10d / %d rows", i+1, num), "memUsed", common.GetMemUsageHuman(), "timeTaken", time.Since(timeStart).String())

	// Load input files
	var sourcelog map[string]map[string]int64 // [hash][source] = timestampMs
	if len(inputSourceLogFiles) > 0 {
		log.Info("Loading sourcelog files...")
		sourcelog, _ = common.LoadSourcelogFiles(log, inputSourceLogFiles)
		log.Infow("Processed input sourcelog files",
			"txTotal", common.Printer.Sprintf("%d", len(sourcelog)),
			"memUsed", common.GetMemUsageHuman(),
		)
	}

	log.Info("Analyzing...")
	analyzer := common.NewAnalyzer2(common.Analyzer2Opts{ //nolint:exhaustruct
		Transactions: entries,
		Sourelog:     sourcelog,
		SourceComps:  sourceComps,
	})

	s := analyzer.Sprint()

	fmt.Println("")
	fmt.Println(s)

	if outFile != "" {
		err = analyzer.WriteToFile(outFile)
		if err != nil {
			log.Errorw("Can't write to file", "error", err)
		}
	}

	return nil
}
