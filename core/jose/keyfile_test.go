package jose

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func kidOf(t *testing.T, path string) string {
	t.Helper()
	key, created, err := LoadOrCreateKey(path, false)
	if err != nil || created {
		t.Fatalf("%v %v", created, err)
	}
	pub, _ := PublicJWK(key)
	return pub["kid"].(string)
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entity.json")
	if _, _, err := LoadOrCreateKey(path, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent and not asked to create: %v", err)
	}
	key, created, err := LoadOrCreateKey(path, true)
	if err != nil || !created || key == nil {
		t.Fatalf("%v %v", created, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key file is private: %v %v", info, err)
	}
	pub, _ := PublicJWK(key)
	if kidOf(t, path) != pub["kid"] {
		t.Fatal("the file holds the key that was returned")
	}
	again, created, err := LoadOrCreateKey(path, true)
	if err != nil || created {
		t.Fatalf("an existing key is loaded, never replaced: %v %v", created, err)
	}
	if p2, _ := PublicJWK(again); p2["kid"] != pub["kid"] {
		t.Fatal("a different key came back")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("no temporary files are left behind: %v", entries)
	}
	if err := os.WriteFile(filepath.Join(dir, "junk.json"), []byte("not a jwk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(filepath.Join(dir, "junk.json"), true); err == nil || !strings.Contains(err.Error(), "JWK") {
		t.Fatalf("an unreadable key file is an error, not replaced: %v", err)
	}
	pubJSON, _ := json.Marshal(pub)
	if err := os.WriteFile(filepath.Join(dir, "public.json"), pubJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(filepath.Join(dir, "public.json"), false); err == nil || !strings.Contains(err.Error(), "private JWK") {
		t.Fatalf("a public key is not a key to sign with: %v", err)
	}
	if _, _, err := LoadOrCreateKey(filepath.Join(dir, "missing-dir", "k.json"), true); err == nil {
		t.Fatal("a directory that does not exist is an error")
	}
}

// Two replicas starting together on a shared volume used to each mint a key and each
// write it; one of them then signed with a key the file no longer held. Whoever loses
// the race now reads and uses the winner's key.
func TestReplicasRacingForTheKeyFileAgree(t *testing.T) {
	for name, noLinks := range map[string]bool{"hard links": false, "no hard links": true} {
		t.Run(name, func(t *testing.T) {
			if noLinks {
				link = func(string, string) error { return &os.LinkError{Op: "link", Err: errors.ErrUnsupported} }
				defer func() { link = os.Link }()
			}
			path := filepath.Join(t.TempDir(), "entity.json")
			const n = 16
			kids := make([]string, n)
			made := make([]bool, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					key, created, err := LoadOrCreateKey(path, true)
					if err != nil {
						t.Errorf("%d: %v", i, err)
						return
					}
					pub, _ := PublicJWK(key)
					kids[i], made[i] = pub["kid"].(string), created
				}(i)
			}
			wg.Wait()
			minted := 0
			for i := range kids {
				if kids[i] != kids[0] {
					t.Fatalf("replicas disagree on the key: %v", kids)
				}
				if made[i] {
					minted++
				}
			}
			if minted != 1 || kidOf(t, path) != kids[0] {
				t.Fatalf("exactly one key is minted, and it is the one in the file: minted=%d", minted)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 1 {
				t.Fatalf("no temporary files are left behind: %v", entries)
			}
		})
	}
}
