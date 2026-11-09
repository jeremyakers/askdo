package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fetchFixture(t *testing.T) (*releaseServer, string, string) {
	t.Helper()
	machine := byte(0x3e)
	if runtime.GOARCH == "arm64" {
		machine = 0xb7
	}
	raw, assets := downloadFixture(t, "v1.2.3", rc21SourceCommit, runtime.GOARCH, elfImage(machine), elfImage(machine))
	server := newReleaseServer(t, "", map[string]string{"v1.2.3": raw}, assets)
	return server, server.URL + "/jeremyakers/askdo", raw
}

func TestFetchManifestReturnsTheDigestAFleetTargetPins(t *testing.T) {
	// Given: a release whose manifest and assets are published.
	server, base, raw := fetchFixture(t)

	// When: only its manifest is fetched.
	manifest, err := FetchManifest(context.Background(), nil, base, "v1.2.3")

	// Then: the digest is the one a plan binds, and nothing but the manifest was requested.
	if err != nil {
		t.Fatal(err)
	}
	if want := hexDigest([]byte(raw)); manifest.Digest != want || manifest.Tag != "v1.2.3" || manifest.SourceCommit != rc21SourceCommit {
		t.Fatalf("manifest = %+v, want digest %s", manifest, want)
	}
	if got := server.requestCount(); got != 1 {
		t.Fatalf("%d requests made, want only the manifest", got)
	}
	// The digest equals what a full download of the same release reports.
	downloaded, err := DownloadRelease(context.Background(), nil, base, "v1.2.3", filepath.Join(t.TempDir(), "dl"))
	if err != nil || downloaded.Digest != manifest.Digest {
		t.Fatalf("download digest %q, err %v; fetch digest %q", downloaded.Digest, err, manifest.Digest)
	}
}

func TestFetchManifestKeepsTheOfficialRepositoryAndTagRules(t *testing.T) {
	server, base, _ := fetchFixture(t)
	for name, tc := range map[string]struct{ base, tag string }{
		"another repository": {server.URL + "/someone/else", "v1.2.3"},
		"another host":       {"https://example.com/jeremyakers/askdo", "v1.2.3"},
		"plain http remote":  {"http://github.com/jeremyakers/askdo", "v1.2.3"},
		"latest":             {base, "latest"},
		"a branch":           {base, "main"},
		"empty tag":          {base, ""},
		"path in tag":        {base, "../v1.2.3"},
		"unpublished tag":    {base, "v9.9.9"},
	} {
		t.Run(name, func(t *testing.T) {
			before := server.requestCount()
			if manifest, err := FetchManifest(context.Background(), nil, tc.base, tc.tag); err == nil {
				t.Fatalf("accepted: %+v", manifest)
			}
			if tc.base != base && server.requestCount() != before {
				t.Fatal("a request left for a repository that is not the official one")
			}
		})
	}
}

func TestFetchManifestRefusesAManifestForAnotherRelease(t *testing.T) {
	// A release URL that serves another tag's manifest is not the release asked for.
	raw, _ := downloadFixture(t, "v1.2.4", rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	server := newReleaseServer(t, "", map[string]string{"v1.2.3": raw}, nil)
	if _, err := FetchManifest(context.Background(), nil, server.URL+"/jeremyakers/askdo", "v1.2.3"); err == nil {
		t.Fatal("manifest for another release accepted")
	}
}

func TestFetchManifestLeavesNothingOnDisk(t *testing.T) {
	_, base, _ := fetchFixture(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if _, err := FetchManifest(context.Background(), nil, base, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("fetching a manifest wrote %v (%v)", entries, err)
	}
}
