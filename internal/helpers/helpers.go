package helpers

import (
	"fmt"
	"os"
	"time"

	mailing "github.com/slayerjk/go-mailing"
)

// Convert given time to local time zone
func ConvertToTZ(timeToConvert *time.Time, timezone string) (time.Time, error) {
	localTz, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to make LoadLocation of given timezone: %s\n%v", timezone, err)
	}

	return timeToConvert.In(localTz), nil
}

// Explain userAccountControl
func ExplainUserAccountControl(statusCode string) string {
	switch statusCode {
	case "512":
		statusCode = statusCode + " NORMAL_ACCOUNT"
	case "8388608":
		statusCode = statusCode + " PASSWORD_EXPIRED"
	case "514":
		statusCode = statusCode + " ACCOUNTDISABLE"
	case "546":
		statusCode = statusCode + " ACCOUNTDISABLE"
	default:
		statusCode = statusCode + " UNKNOWN"
	}

	return statusCode
}

// form report from log file
func formReportFromFile(logPath string) (string, error) {
	// check if file exists
	if _, err := os.Stat(logPath); err != nil {
		return "", err
	}

	// read
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// send plain text mail report
// "html", *mailHost, *mailPort, *mailFrom, *mailSubject, body, []string{newUser.email}, []string{newUser.qrPath}
func SendReport(
	mailHost string, mailPort int, mailFrom string, mailSubject string,
	filePathToReport string, adminsList []string, attch []string) error {

	// get log text
	reportBody, err := formReportFromFile(filePathToReport)
	if err != nil {
		return fmt.Errorf("failed to form report from file: %s, %v", filePathToReport, err)
	}

	// send mail
	err = mailing.SendEmailWoAuth("plain", mailHost, mailPort, mailFrom, mailSubject, reportBody, adminsList, nil)
	if err != nil {
		return fmt.Errorf("failed to send report: %v, %v", adminsList, err)
	}

	return nil
}
