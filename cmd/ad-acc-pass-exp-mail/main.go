package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/slayerjk/ad-acc-pass-exp-mail/internal/helpers"
	mailing "github.com/slayerjk/go-mailing"
	vafswork "github.com/slayerjk/go-vafswork"
	ldapwork "github.com/slayerjk/go-valdapwork"
)

const (
	appName = "ad-acc-pass-exp-mail"
)

type account struct {
	name                string
	accStatus           string
	pwdLastSet          string
	pwdLastSetConverted time.Time
	expirationStatus    string
}

func main() {
	// defining default values
	var (
		workDir          string    = vafswork.GetExePath()
		logsPathDefault  string    = workDir + "/logs" + "_" + appName
		startTime        time.Time = time.Now()
		accountsToNotify []account
		accountsFailed   []account
	)

	// starting wait group
	var wg sync.WaitGroup
	wg.Add(1)

	// defining chans
	chanEnrichStatus := make(chan account)
	chanConvertPwSetDate := make(chan account)
	chanCheckPwSetDate := make(chan account)

	// flags
	logsDir := flag.String("log-dir", logsPathDefault, "set custom log dir")
	logsToKeep := flag.Int("keep-logs", 7, "set number of logs to keep after rotation")
	passExpThreshold := flag.Int("pet", 60, "password expiration threshold(after this threshold password will be expired), days")
	passNotifyThreshold := flag.Int("pnt", 5, "days before expiration for notification, days")
	mailHost := flag.String("mhost", "NONE", "REQUIRED, SMTP host, name or IP")
	mailPort := flag.Int("mport", 25, "SMTP host's port")
	mailFrom := flag.String("mfrom", "NONE", "REQUIRED, mail from address")
	mailTo := flag.String("mto", "NONE", "REQUIRED, mail to, email addresses separated by coma")
	mailToAdmins := flag.String("mtoa", "NONE", "mail to admins if errors occured(send log), email addresses separated by coma")
	mailSubject := flag.String("msubj", "Accounts with expired password", "mail subject for expired passwords")
	ldapFqdn := flag.String("lfqdn", "NONE", "REQUIRED, FQDN of your LDAP(AD)")
	baseDn := flag.String("basedn", "NONE", "REQUIRED, accounts' baseDN(OU) to search in AD, ex.:'OU=service accounts,OU=busines,DC=example,DC=com'")
	bindUser := flag.String("bu", "NONE", "REQUIRED, bind user, 'USER@DOMAIN'")
	bindUserPassword := flag.String("bup", "NONE", "REQUIRED, bind user password")
	timeZone := flag.String("tz", "Asia/Almaty", "your timezone from time zone db, ex:'Asia/Almaty', must be correct")

	flag.Usage = func() {
		fmt.Println("AD accounts password expiration mail notification")
		fmt.Println("Version = v0.0.1")
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
	case *bindUser == "NONE":
		logger.Error("-bu flag is not set, exiting")
		fmt.Println("-bu flag is not set, exiting")
		os.Exit(1)
	case *bindUserPassword == "NONE":
		logger.Error("-bup flag is not set, exiting")
		fmt.Println("-bup flag is not set, exiting")
		os.Exit(1)
	default:
		logger.Info("all required flags are set")
	}

	// making list of users to notify
	mailToList := make([]string, 0)
	for _, addr := range strings.Split(*mailTo, ",") {
		mailToList = append(mailToList, strings.Trim(addr, " "))
	}

	// check admins mails
	// skip if "NONE" or wrong mails
	mailToAdminIsOn := false
	adminsList := make([]string, 0)
	reportSubject := "Err Report"
	if *mailToAdmins != "NONE" {
		for _, addr := range strings.Split(*mailToAdmins, ",") {
			adminsList = append(adminsList, strings.Trim(addr, " "))
		}
		mailToAdminIsOn = true
	}

	// make LDAP connection
	logger.Info("trying to make LDAP connection")
	ldapCon, err := ldapwork.MakeLdapConnection(*ldapFqdn)
	if err != nil {
		logger.Error("failed to make LDAP connection, exiting", "err", err)

		// send report to admin
		if mailToAdminIsOn {
			logger.Info("sending admin report")
			err := mailing.SendReport(*mailHost, *mailPort, *mailFrom, reportSubject, logFilePath, adminsList, nil)
			if err != nil {
				logger.Warn("failed to send mail to admins", "admins", adminsList, "err", err)
			}
		}

		os.Exit(1)
	}
	defer ldapCon.Close()

	// make LDAP bind
	logger.Info("trying to make LDAP bind")
	err = ldapwork.LdapBind(ldapCon, *bindUser, *bindUserPassword)
	if err != nil {
		logger.Error("failed to make LDAP bind, exiting", slog.Any("user", bindUser), slog.Any("err", err))

		// send report to admin
		if mailToAdminIsOn {
			logger.Info("sending admin report")
			err := mailing.SendReport(*mailHost, *mailPort, *mailFrom, reportSubject, logFilePath, adminsList, nil)
			if err != nil {
				logger.Warn("failed to send mail to admins", "admins", adminsList, "err", err)
			}
		}

		os.Exit(1)
	}

	// form ldap filter
	ldapFilter := "(objectClass=user)"

	// get ad accounts from OU
	logger.Info("trying to make LDAP search request")
	ldapResponse, err := ldapwork.MakeSearchReq(ldapCon, *baseDn, ldapFilter, "*")
	if err != nil {
		logger.Error("failed to get response from LDAP", "err", err)

		// send report to admin
		if mailToAdminIsOn {
			logger.Info("sending admin report")
			err := mailing.SendReport(*mailHost, *mailPort, *mailFrom, reportSubject, logFilePath, adminsList, nil)
			if err != nil {
				logger.Warn("failed to send mail to admins", "admins", adminsList, "err", err)
			}
		}

		os.Exit(1)
	}

	// collect ldap attributes
	go func() {
		logger.Info("collecting accounts data")

		for _, entry := range ldapResponse {
			chanEnrichStatus <- account{
				name:       entry.GetAttributeValue("sAMAccountName"),
				accStatus:  entry.GetAttributeValue("userAccountControl"),
				pwdLastSet: entry.GetAttributeValue("pwdLastSet"),
			}

			// DEBUG
			// entry.PrettyPrint(4)
		}

		close(chanEnrichStatus)
	}()

	// enriching account status
	go func() {
		for {
			acc, ok := <-chanEnrichStatus
			if !ok {
				break
			}

			// enrich acc status info
			logger.Info("enriching account's status code", "name", acc.name)
			acc.accStatus = helpers.ExplainUserAccountControl(acc.accStatus)

			chanConvertPwSetDate <- acc
		}
		close(chanConvertPwSetDate)
	}()

	// normalize pwLastSet: convert to time.Time and set TZ
	go func() {
		for {
			acc, ok := <-chanConvertPwSetDate
			if !ok {
				break
			}

			logger.Info("trying to convert pwdLastSet", "name", acc.name)

			timeToConvert, err := strconv.Atoi(acc.pwdLastSet)
			if err != nil {
				logger.Warn("failed to convert pwdLastSet to int, skipping", "name", acc.name, "pwdLastSet", acc.pwdLastSet, "err", err)
				accountsFailed = append(accountsFailed, acc)
				chanCheckPwSetDate <- account{name: "SKIP"}
				continue
			}

			// get convertedTime
			convertedTime := ldapwork.ConvertPwdLastSetAttr(int64(timeToConvert))

			// DEBUG
			// fmt.Println("converted to utc", acc.name, convertedTime)

			// add timezone
			convertedTimeTz, err := helpers.ConvertToTZ(&convertedTime, *timeZone)
			if err != nil {
				logger.Warn("failed to convert pwdLastSet to local TZ, skipping", "name", acc.name, "pwdLastSet", convertedTime, "err", err)
				accountsFailed = append(accountsFailed, acc)
				chanCheckPwSetDate <- account{name: "SKIP"}
				continue
			}

			// DEBUG
			// fmt.Println("converted to TZ", acc.name, convertedTimeTz)

			acc.pwdLastSetConverted = convertedTimeTz

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

			if acc.name == "SKIP" {
				continue
			}

			// defining expiration date
			expiratonDate := acc.pwdLastSetConverted.AddDate(0, 0, *passExpThreshold)
			expirationDateStr := expiratonDate.Format("02.01.2006 15:04")
			// setting start notification date
			startNotificationDate := expiratonDate.AddDate(0, 0, -*passNotifyThreshold)

			// DEBUG
			// fmt.Println("exp date", acc.name, expirationDateStr)

			// checking if already expired
			logger.Info("checking if password already expired", "name", acc.name, "last set", acc.pwdLastSetConverted)
			if expiratonDate.Before(startTime) || expiratonDate.Equal(startTime) {
				logger.Warn("password already expired", "name", acc.name, "last set", acc.pwdLastSetConverted)
				acc.expirationStatus = fmt.Sprintf("EXPIRED: %s", expirationDateStr)
				accountsToNotify = append(accountsToNotify, acc)
				continue
			}

			// checking if to notify
			logger.Info("checking if to notify", "name", acc.name, "last set", acc.pwdLastSetConverted)

			if startTime.After(startNotificationDate) {
				logger.Info("password is going to be expired", "name", acc.name, "last set", acc.pwdLastSetConverted, "expDate", expirationDateStr)
				acc.expirationStatus = fmt.Sprintf("WILL BE EXPIRED SOON -> %s", expirationDateStr)
				accountsToNotify = append(accountsToNotify, acc)
			}
		}

		// stopping wg
		wg.Done()
	}()

	// wait all goroutines done
	wg.Wait()

	// DEBUG
	// for _, acc := range accountsToNotify {
	// 	fmt.Println(acc)
	// }
	// fmt.Println("failed:", accountsFailed)

	// if there is at least one expired/about to expire pwd acc
	if len(accountsToNotify) > 0 {

		// forming body
		var mailBody strings.Builder
		for _, acc := range accountsToNotify {
			mailBody.WriteString(
				fmt.Sprintf("sAMAccountName: %s\naccStatus: %s\npwdLastSet: %v\nexpirationStatus: %s\n---\n",
					acc.name,
					acc.accStatus,
					acc.pwdLastSetConverted,
					acc.expirationStatus),
			)
		}

		// sending mail
		err := mailing.SendEmailWoAuth("plain", *mailHost, *mailPort, *mailFrom, *mailSubject, mailBody.String(), mailToList, nil)
		if err != nil {
			logger.Error("failed to send mail about accounts", "err", err)
			// send report to admin
			if mailToAdminIsOn {
				logger.Info("sending admin report")
				err := mailing.SendReport(*mailHost, *mailPort, *mailFrom, reportSubject, logFilePath, adminsList, nil)
				if err != nil {
					logger.Warn("failed to send mail to admins", "admins", adminsList, "err", err)
				}
			}

			os.Exit(1)
		}
	}

	// sending report(if any failed acc)
	if len(accountsFailed) > 0 {
		// send report to admin
		if mailToAdminIsOn {
			var mailBody strings.Builder
			for _, acc := range accountsFailed {
				mailBody.WriteString(
					fmt.Sprintf("sAMAccountName: %s\naccStatus: %s\npwdLastSet: %v\nexpirationStatus: %s\n---\n",
						acc.name,
						acc.accStatus,
						acc.pwdLastSetConverted,
						acc.expirationStatus),
				)
			}
			logger.Info("sending admin report")
			err := mailing.SendEmailWoAuth("plain", *mailHost, *mailPort, *mailFrom, "FAILED accounts", mailBody.String(), adminsList, nil)
			if err != nil {
				logger.Warn("failed to send mail to admins", "admins", adminsList, "err", err)
			}
		}
	}

	// count & print estimated time
	logger.Info("Program Done", slog.Any("estimated time(sec)", time.Since(startTime).Seconds()))
}
