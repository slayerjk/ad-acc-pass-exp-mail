package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	// change this path for your project

	"github.com/slayerjk/ad-acc-pass-exp-mail/internal/helpers"
	vafswork "github.com/slayerjk/go-vafswork"
	ldapwork "github.com/slayerjk/go-valdapwork"
	"golang.org/x/term"
	// mailing "github.com/slayerjk/go-mailing"
	// vawebwork "github.com/slayerjk/go-vawebwork"
)

const (
	appName = "ad-acc-pass-exp-mail"
)

type account struct {
	name                string
	accStatus           string
	pwdLastSet          string
	pwdLastSetConverted *time.Time
}

func main() {
	// defining default values
	var (
		workDir          string    = vafswork.GetExePath()
		logsPathDefault  string    = workDir + "/logs" + "_" + appName
		startTime        time.Time = time.Now()
		bindUser         string
		bindUserPassword string
		// accountsToNotify []account
		accountsFailed []account
	)

	// starting wait group
	var wg sync.WaitGroup
	wg.Add(1)

	// defining chans
	chanCheckStatus := make(chan account)
	chanCheckPwSetDate := make(chan account)

	// flags
	logsDir := flag.String("log-dir", logsPathDefault, "set custom log dir")
	logsToKeep := flag.Int("keep-logs", 7, "set number of logs to keep after rotation")
	// passExpThreshold := flag.Int("pet", 60, "password expiration threshold(after this threshold password will be expired), days")
	// passNotifyThreshold := flag.Int("pnt", 50, "password notification threshold(after this threshold start to notify users), days")
	mailHost := flag.String("mhost", "NONE", "SMTP host, name or IP")
	// mailPort := flag.Int("mport", 25, "SMTP host's port")
	mailFrom := flag.String("mfrom", "NONE", "mail from address")
	mailTo := flag.String("mto", "NONE", "mail to, email addresses separated by coma")
	ldapFqdn := flag.String("lfqdn", "NONE", "FQDN of your LDAP(AD)")
	baseDn := flag.String("basedn", "NONE", "accounts' baseDN(OU) to search in AD, ex.:'OU=service accounts,OU=busines,DC=example,DC=com'")
	// timeZone := flag.String("tz", "Asia/Almaty", "your timezone from time zone db, ex:'Asia/Almaty', must be correct")

	flag.Usage = func() {
		fmt.Println("AD accounts password expiration mail notification")
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

	// checking flags
	switch {
	case *mailHost == "NONE":
		logger.Error("-mhost flag is not set, exiting")
		fmt.Println("-mhost flag is not set, exiting")
		os.Exit(1)
	case *mailFrom == "NONE":
		logger.Error("-mfrom flag is not set, exiting")
		fmt.Println("-mfrom flag is not set, exiting")
		os.Exit(1)
	case *mailTo == "NONE":
		logger.Error("-mto flag is not set, exiting")
		fmt.Println("-mto flag is not set, exiting")
		os.Exit(1)
	case *ldapFqdn == "NONE":
		logger.Error("-lfqdn flag is not set, exiting")
		fmt.Println("-lfqdn flag is not set, exiting")
		os.Exit(1)
	case *baseDn == "NONE":
		logger.Error("-basedn flag is not set, exiting")
		fmt.Println("-basedn flag is not set, exiting")
		os.Exit(1)
	default:
		logger.Info("all flags are set")
	}

	// getting LDAP bind user & password
	fmt.Print("Enter AD bind user name(<USERNAME>@<YOUR DOMAIN>): ")
	fmt.Scan(&bindUser)
	fmt.Print("Enter AD bind user password: ")
	byteBindUserPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("failed to get AD bind user password", "err", err)
		os.Exit(1)
	}
	bindUserPassword = string(byteBindUserPassword)
	fmt.Println()

	// making list of users to notify
	mailToList := make([]string, 0)
	for _, addr := range strings.Split(*mailTo, ",") {
		mailToList = append(mailToList, strings.Trim(addr, " "))
	}

	// make LDAP connection
	logger.Info("trying to make LDAP connection")
	ldapCon, err := ldapwork.MakeLdapConnection(*ldapFqdn)
	if err != nil {
		logger.Error("failed to make LDAP connection, exiting", "err", err)
		os.Exit(1)
	}
	defer ldapCon.Close()

	// make LDAP bind
	logger.Info("trying to make LDAP bind")
	err = ldapwork.LdapBind(ldapCon, bindUser, bindUserPassword)
	if err != nil {
		logger.Error("failed to make LDAP bind, exiting", slog.Any("user", bindUser), slog.Any("err", err))
		os.Exit(1)
	}

	// form ldap filter
	ldapFilter := "(objectClass=user)"

	// get ad accounts from OU
	logger.Info("trying to make LDAP search request")
	ldapResponse, err := ldapwork.MakeSearchReq(ldapCon, *baseDn, ldapFilter, "*")
	if err != nil {
		logger.Error("failed to get response from LDAP", "err", err)
		os.Exit(1)
	}

	// collect ldap attributes
	logger.Info("collecting accounts data")
	for _, entry := range ldapResponse {
		chanCheckStatus <- account{
			name:       entry.GetAttributeValue("sAMAccountName"),
			accStatus:  entry.GetAttributeValue("userAccountControl"),
			pwdLastSet: entry.GetAttributeValue("pwdLastSet"),
		}

		// pwLastSetAttr := entry.GetAttributeValue("pwdLastSet")
		// pwLastSetAttrInt, err := strconv.Atoi(pwLastSetAttr)
		// if err != nil {
		// 	logger.Warn("failed to convert 'pwdLastSet' to int", "pwdLastSet", pwLastSetAttr, "err", err)
		// }

		// pwLastSetAttrConverted := helpers.ConvertPwdLastSet(int64(pwLastSetAttrInt))
		// fmt.Println("UTC time:", pwLastSetAttrConverted)

		// pwLastSet, err := helpers.ConvertToTZ(&pwLastSetAttrConverted, *timeZone)
		// if err != nil {
		// 	logger.Warn("failed to convert given time to local timezon", "err", err)
		// }
		// fmt.Println("Local time:", pwLastSet)

		// entry.PrettyPrint(2)

		// count threshold days
		// time.Now().Sub(pwLastSet)
	}
	close(chanCheckStatus)

	// check account status
	go func() {
		for {
			acc, ok := <-chanCheckStatus
			if !ok {
				break
			}

			// enrich acc status info
			logger.Info("enriching account's status code", "name", acc.name)
			acc.accStatus = helpers.ExplainUserAccountControl(acc.accStatus)

			// pass to chan
			chanCheckPwSetDate <- acc
		}
		close(chanCheckPwSetDate)

	}()

	// check account pwdLastSet if already expired
	go func() {
		for {
			acc, ok := <-chanCheckPwSetDate
			if !ok {
				break
			}

			logger.Info("trying to convert pwdLastSet", "name", acc.name)
			timeToConvert, err := strconv.Atoi(acc.pwdLastSet)
			if err != nil {
				logger.Warn("failed to convert pwdLastSet to int, skipping", "name", acc.name, "pwdLastSet", acc.pwdLastSet, "err", err)
				accountsFailed = append(accountsFailed, acc)
				// TODO: send something(?) to chan(?)
				continue
			}

			// get convertedTime
			convertedTime := ldapwork.ConvertPwdLastSetAttr(int64(timeToConvert))
			fmt.Println(convertedTime)

			// check if already expired
			// check status first

		}
		close(chanCheckPwSetDate)
	}()

	// wait all goroutines done
	wg.Wait()

	// sending mail

	// sending report(if any failed acc)

	// count & print estimated time
	logger.Info("Program Done", slog.Any("estimated time(sec)", time.Since(startTime).Seconds()))
}
