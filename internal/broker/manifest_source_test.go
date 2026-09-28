package broker

import (
	"fmt"
	"reflect"
	"testing"
)

func TestWithheldFactsOnlyBrokerObservedStableAndBounded(t *testing.T) {
	j := &jobRuntime{withheldPaths: map[string]struct{}{"/work/z.env": {}, "/work/a.env": {}}}
	index := captureIndex{Files: []captureRecord{{Path: "/work/a.env", Masked: true}, {Path: ".env", Masked: true}, {Path: "visible.sh"}}}
	refs, count := j.withheldFacts(index)
	if count != 3 || !reflect.DeepEqual(refs, []string{".env", "/work/a.env", "/work/z.env"}) {
		t.Fatalf("refs=%v count=%d", refs, count)
	}
	for n := 0; n < 20; n++ {
		j.withheldPaths[fmt.Sprintf("/work/%02d.env", n)] = struct{}{}
	}
	refs, count = j.withheldFacts(index)
	if count != 23 || len(refs) != 16 {
		t.Fatalf("refs=%v count=%d", refs, count)
	}
}
