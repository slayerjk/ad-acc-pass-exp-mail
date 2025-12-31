package helpers

import (
	"math"
	"time"
)

// Convert LDAP attribute time 'pwdLastSet' to time.Time with given timezon
// Thanks to https://stackoverflow.com/questions/57901280/calculate-time-time-from-timestamp-starting-from-1601-01-01-in-go
func ConvertPwdLastSet(input int64, timezone string) time.Time {
	maxd := time.Duration(math.MaxInt64).Truncate(100 * time.Nanosecond)
	maxdUnits := int64(maxd / 100) // number of 100-ns units

	t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	for input > maxdUnits {
		t = t.Add(maxd)
		input -= maxdUnits
	}
	if input != 0 {
		t = t.Add(time.Duration(input * 100))
	}
	return t
}
