package freebusy

import "time"

type RFC3339 string

func NewRFC3339(value time.Time) RFC3339 {
	return RFC3339(value.Format(time.RFC3339))
}

func (value RFC3339) Time() (time.Time, error) {
	return time.Parse(time.RFC3339, string(value))
}

type Window struct {
	Start time.Time
	End   time.Time
}

type AvailableInterval struct {
	Start RFC3339 `json:"start"`
	End   RFC3339 `json:"end"`
}

type View struct {
	AvailableIntervals []AvailableInterval `json:"available_intervals"`
}
