package utils

import (
	"github.com/hako/durafmt"
	"github.com/statping/statping/types/core"
	"time"
)

// Now returns the UTC timestamp
func Now() time.Time {
	return time.Now().UTC()
}

func TimeFormat(t time.Time) string {
	loc, _ := time.LoadLocation(core.App.TimeZone)
	return t.In(loc).String()
}

type Duration struct {
	time.Duration
}

func (d Duration) Human() string {
	return durafmt.Parse(d.Duration).LimitFirstN(2).String()
}

// FormatDuration converts a time.Duration into a string
func FormatDuration(d time.Duration) string {
	return durafmt.ParseShort(d).LimitFirstN(3).String()
}
