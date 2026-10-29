package violation

import (
	"errors"
	"testing"
)

func TestReportDedupeAndRetry(t *testing.T) {
	var got [][]Item
	fail := true
	Register("n1", func(items []Item) error {
		if fail {
			fail = false
			return errors.New("down")
		}
		got = append(got, items)
		return nil
	})
	defer Unregister("n1")

	Report("n1", Item{UID: 1, Kind: KindBT})
	Report("n1", Item{UID: 1, Kind: KindBT})
	Report("n1", Item{UID: 1, Kind: KindSSH})
	Report("unknown", Item{UID: 2, Kind: KindBT})
	Report("n1", Item{UID: 0, Kind: KindBT})

	flush()
	if len(got) != 0 {
		t.Fatal("should fail first time")
	}
	flush()
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("unexpected batches: %+v", got)
	}
}
