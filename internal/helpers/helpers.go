package helpers

import (
	"fmt"
	"time"
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
