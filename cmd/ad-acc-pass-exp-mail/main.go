package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	// change this path for your project

	vafswork "github.com/slayerjk/go-vafswork"
	// mailing "github.com/slayerjk/go-mailing"
	// vawebwork "github.com/slayerjk/go-vawebwork"
)

const (
	appName = "MY-APP"
)

// for dep injection
// type application struct {
// 	logger *slog.Logger
// }

func main() {
	// defining default values
	var (
		workDir         string    = vafswork.GetExePath()
		logsPathDefault string    = workDir + "/logs" + "_" + appName
		startTime       time.Time = time.Now()
		// mailingFileDefault       string = workDir + "/data/mailing.json"
	)

	// flags
	logsDir := flag.String("log-dir", logsPathDefault, "set custom log dir")
	logsToKeep := flag.Int("keep-logs", 7, "set number of logs to keep after rotation")
	// mailingFile := flag.String("m-file", mailingFileDefault, "file with mailing settings")

	flag.Usage = func() {
		fmt.Println("APP DESCRIPTION")
		fmt.Println("Version = x.x.x")
		fmt.Println("Usage: <app> [-opt] ...")
		fmt.Println("Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()

	// logging
	// create log dir
	if err := os.MkdirAll(*logsDir, os.ModePerm); err != nil {
		fmt.Fprintf(os.Stdout, "failed to create log dir %s:\n\t%v", *logsDir, err)
		os.Exit(1)
	}
	// set current date
	dateNow := time.Now().Format("02.01.2006")
	// create log file
	logFilePath := fmt.Sprintf("%s/%s_%s.log", *logsDir, appName, dateNow)
	// open log file in append mode
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stdout, "failed to open created log file %s:\n\t%v", logFilePath, err)
		os.Exit(1)
	}
	defer logFile.Close()
	// set logger
	logger := slog.New(slog.NewTextHandler(logFile, nil))
	// test logger
	// logger.Info("info test-1", slog.Any("val", "key"))

	// starting programm notification
	logger.Info("Program Started", "app name", appName)

	// rotate logs
	logger.Info("Log rotation first", "logsDir", *logsDir, "logs to keep", *logsToKeep)
	if err := vafswork.RotateFilesByMtime(*logsDir, *logsToKeep); err != nil {
		fmt.Fprintf(os.Stdout, "failed to rotate logs:\n\t%v", err)
	}

	// setting application struct with dep injection
	// app := &application{
	// 	logger: logger,
	// }

	// main code here
	//
	//

	// count & print estimated time
	logger.Info("Program Done", slog.Any("estimated time(sec)", time.Since(startTime).Seconds()))
}
