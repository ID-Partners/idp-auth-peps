package jose

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// link publishes a fully written key file under its final name. A variable so a test
// can take hard links away.
var link = os.Link

// LoadOrCreateKey reads the private JWK at path. When there is no file and create is
// set, it mints a P-256 key and publishes it at path only if nothing is there yet, so
// that replicas starting together on a shared volume all end up signing with one key:
//
//   - the key is written in full to a private (0600) temporary file beside path and
//     synced, then hard-linked into place. Unlike a rename, which would silently
//     replace a key another replica published a moment earlier, a link fails if path
//     exists — and the file appears complete or not at all;
//   - where the filesystem has no hard links, path itself is created with O_EXCL
//     (0600) and written;
//   - whoever loses either race reads the winner's key and returns that.
//
// created reports whether this call minted the key. A file that exists but does not
// hold a private JWK is an error, and is never replaced.
func LoadOrCreateKey(path string, create bool) (key crypto.Signer, created bool, err error) {
	key, err = readKeyFile(path)
	if err != nil && create && !errors.Is(err, os.ErrNotExist) {
		// Perhaps another replica is writing it right now (without hard links, the file
		// exists before it is complete). A file that is really unreadable still fails.
		key, err = readSettled(path)
	}
	if err == nil || !errors.Is(err, os.ErrNotExist) || !create {
		return key, false, err
	}
	fresh, err := GenerateKey()
	if err != nil {
		return nil, false, err
	}
	// Neither can fail: a P-256 key always renders, and the JWK is all strings.
	jwk, _ := PrivateJWK(fresh)
	raw, _ := json.MarshalIndent(jwk, "", "  ")
	won, err := publish(path, raw)
	if err != nil {
		return nil, false, err
	}
	if won {
		return fresh, true, nil
	}
	// Another process published first: its key is the key.
	key, err = readSettled(path)
	return key, false, err
}

// publish puts raw at path unless something is already there, and reports whether it
// did.
func publish(path string, raw []byte) (bool, error) {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+rand.Text())
	if err := writeNew(tmp, raw); err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	err := link(tmp, path)
	if err != nil && !errors.Is(err, os.ErrExist) {
		// No hard links on this filesystem: claim the name itself.
		err = writeNew(path, raw)
	}
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// The new directory entry is durable too, where the platform allows it.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return true, nil
}

// writeNew creates name, which must not exist, private to its owner, and writes raw to
// it, synced. A failure after the file was created removes it.
func writeNew(name string, raw []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

func readKeyFile(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("%s is not a JWK: %v", path, err)
	}
	key, err := PrivateKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("%s is not a usable private JWK: %v", path, err)
	}
	return key, nil
}

// readSettled reads a key another process has just published. Linked into place, it
// is complete the moment it exists; created with O_EXCL, it may still be being
// written, so a read that fails is retried for a moment.
func readSettled(path string) (crypto.Signer, error) {
	key, err := readKeyFile(path)
	for i := 0; err != nil && i < 40; i++ {
		time.Sleep(25 * time.Millisecond)
		key, err = readKeyFile(path)
	}
	return key, err
}
