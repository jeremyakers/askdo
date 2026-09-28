// Package jobid defines the canonical, human-facing job ID syntax. It does
// not allocate sequences or read the clock; the store owns both decisions.
package jobid

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Validate accepts YYYY-MM-DD_#N only for a real calendar date and an
// unpadded, positive signed 64-bit decimal sequence.
func Validate(id string) error {
	day, sequence, ok := strings.Cut(id, "_#")
	if !ok {
		return errors.New("job ID must be YYYY-MM-DD_#N")
	}
	if err := validateDay(day); err != nil {
		return err
	}
	n, err := strconv.ParseInt(sequence, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != sequence {
		return errors.New("job ID sequence must be an unpadded positive int64")
	}
	return nil
}

// Format joins a caller-supplied day and allocated sequence without consulting
// wall-clock time.
func Format(day string, sequence int64) (string, error) {
	if err := validateDay(day); err != nil {
		return "", err
	}
	if sequence <= 0 {
		return "", errors.New("job ID sequence must be positive")
	}
	return fmt.Sprintf("%s_#%d", day, sequence), nil
}

func validateDay(day string) error {
	if len(day) != len("2006-01-02") || day[4] != '-' || day[7] != '-' {
		return errors.New("job ID date must be YYYY-MM-DD")
	}
	for i := range day {
		if i == 4 || i == 7 {
			continue
		}
		if day[i] < '0' || day[i] > '9' {
			return errors.New("job ID date must be YYYY-MM-DD")
		}
	}
	date, err := time.Parse("2006-01-02", day)
	if err != nil || date.Year() == 0 || date.Format("2006-01-02") != day {
		return errors.New("job ID date must be a real calendar date")
	}
	return nil
}
