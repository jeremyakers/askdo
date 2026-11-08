package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestCatalogCarriesReviewerWebfetchPolicy(t *testing.T) {
	service, host, _, _, _ := sessionFixture(t, http.NotFoundHandler(), time.Second, 1)
	flag := func(v bool) *bool { return &v }
	for _, tc := range []struct {
		name string
		set  *bool
	}{{"absent", nil}, {"true", flag(true)}, {"false", flag(false)}} {
		t.Run(tc.name, func(t *testing.T) {
			service.cfg.ReviewerWebfetchEnabled = tc.set
			catalog, err := service.catalog(host, 1001)
			if err != nil {
				t.Fatal(err)
			}
			got := catalog.ReviewerWebfetchEnabled
			if (got == nil) != (tc.set == nil) || got != nil && *got != *tc.set {
				t.Fatalf("catalog policy %v, want %v", got, tc.set)
			}
			if err := fleetproto.Validate(catalog); err != nil {
				t.Fatal(err)
			}
		})
	}
}
