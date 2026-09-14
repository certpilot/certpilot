//go:build !windows

package agent

// Everywhere that is not Windows has no certificate store to install into.
//
// Not "not implemented yet". Linux has no equivalent of LocalMachine\My — the
// nearest thing, /etc/ssl/certs, is a directory of trusted roots and not a place
// a server looks up its own key by thumbprint — so a destination naming a store
// here is a spec written for the wrong host, and the useful thing to do with it
// is say so when the file is read.
//
// The refusal lives in validateStore, alongside every other reason a spec can be
// wrong. What is here is the answer to "does this platform have one" and a
// certStore that cannot be called by accident: the installer holds the interface
// unconditionally, so something has to fill it, and a nil there would be a
// panic on a host whose spec has a typo in it.

import "errors"

// storeSupported reports whether this platform has a certificate store the
// agent can install into.
func storeSupported() bool { return false }

// defaultCertStore is what an installer uses when nothing replaced it.
func defaultCertStore() certStore { return noStore{} }

type noStore struct{}

var errNoStore = errors.New(
	"this platform has no certificate store; a destination here writes files")

func (noStore) importPFX(storeName, []byte, string) ([]string, error) { return nil, errNoStore }
func (noStore) thumbprintNamed(storeName, string) (string, error)     { return "", errNoStore }
func (noStore) setFriendlyName(storeName, string, string) error       { return errNoStore }
func (noStore) remove(storeName, string) error                        { return errNoStore }
