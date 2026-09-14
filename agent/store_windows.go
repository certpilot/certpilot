//go:build windows

package agent

// The certificate store, through CryptoAPI.
//
// # Why not Import-PfxCertificate
//
// Every article on this subject reaches for PowerShell, and the agent could
// have. It does not, for three reasons that all point the same way.
//
// Import-PfxCertificate takes a *path*. Handing it one means writing a PKCS#12
// holding the private key to disk, with a password, so that another process can
// read it back — a private key nobody is tracking, sitting in a temporary
// directory, for exactly as long as it takes something to go wrong. This
// package already refuses to leave a `server.key.bak` behind for that reason.
// PFXImportCertStore takes the bytes, so the blob is built in memory, imported,
// and never exists anywhere a backup could find it.
//
// Second, PowerShell is not always available to run arbitrary pipelines: a
// hardened server can be in Constrained Language Mode, and an execution policy
// can refuse. A certificate importing correctly on one host and failing on
// another because of a language mode is a bad day.
//
// Third, what comes back from a cmdlet is a string. What comes back from here
// is the actual error the operating system raised, which is the difference
// between "Import-PfxCertificate : An internal error occurred" and being told
// which store could not be opened.
//
// # The chain goes to CA, and the root goes nowhere
//
// A PKCS#12 carries the issued certificate and the intermediates above it.
// Schannel — which is what IIS, Exchange and everything else on this list
// actually serves TLS with — builds the chain it presents from the machine's CA
// store, not from whatever was imported alongside the leaf. So intermediates
// left out are intermediates never sent, which is the same defect as an nginx
// configuration naming cert.pem instead of fullchain.pem: every browser accepts
// it from a cache and no fresh client does.
//
// So the leaf goes into the store the destination names and the intermediates
// go into CA in the same location.
//
// A self-signed certificate in the chain — the root — is imported nowhere. The
// store that would make it work is Root, and adding to Root is not installing a
// certificate, it is making a certificate authority trusted by every program on
// the machine. That is a decision for whoever administers the host, taken
// deliberately and once, and not a side effect of a renewal at three in the
// morning. What the agent does instead is say which certificates it did not
// import and why.
//
// # The private key is not exportable, and is deleted with its certificate
//
// Imported with PKCS12_ALWAYS_CNG_KSP and without CRYPT_EXPORTABLE. This
// project's central claim is that a key is generated on the host and never
// leaves it; a key marked exportable is one an operator can be talked into
// exporting, and the claim would be a hope. It costs the ability to copy the
// key to a second machine, which is what a second enrolment is for.
//
// Deleting a certificate from a store does not delete its private key — the key
// lives in the KSP and the certificate merely points at it — so a naive
// implementation leaks one key blob per renewal, forever, on every host. The
// key is therefore acquired and deleted explicitly before the certificate is,
// which is the whole reason the import forces CNG: it makes that one call
// rather than two paths.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The two certificate context properties this file reads and writes:
// CERT_FRIENDLY_NAME_PROP_ID, which is how the agent recognises its own work,
// and CERT_KEY_PROV_INFO_PROP_ID, which is how it tells the leaf from the
// intermediates.
//
// Declared here, with the calls that use them, because x/sys/windows exposes
// neither the constants nor the two crypt32 functions that take them. They are
// ordinary exports, and this is the documented way to reach one that has no
// wrapper yet.
const (
	certFriendlyNamePropID = 11
	certKeyProvInfoPropID  = 2
)

var (
	modcrypt32 = windows.NewLazySystemDLL("crypt32.dll")
	modncrypt  = windows.NewLazySystemDLL("ncrypt.dll")

	procCertGetCertificateContextProperty = modcrypt32.NewProc("CertGetCertificateContextProperty")
	procCertSetCertificateContextProperty = modcrypt32.NewProc("CertSetCertificateContextProperty")
	procNCryptDeleteKey                   = modncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject                  = modncrypt.NewProc("NCryptFreeObject")
)

// storeSupported reports whether this platform has a certificate store the
// agent can install into. It is the platform's answer, not a build tag the
// callers have to know about.
func storeSupported() bool { return true }

// windowsStore is the real implementation of certStore.
type windowsStore struct{}

// defaultCertStore is what an installer uses when nothing replaced it.
func defaultCertStore() certStore { return windowsStore{} }

// locationFlag turns LocalMachine or CurrentUser into the high word
// CertOpenStore wants.
func locationFlag(location string) uint32 {
	if location == "CurrentUser" {
		return windows.CERT_SYSTEM_STORE_CURRENT_USER
	}
	return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
}

// openStore opens one system store for writing.
func openStore(sn storeName) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(sn.name)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CertOpenStore(
		uintptr(windows.CERT_STORE_PROV_SYSTEM),
		0, 0,
		locationFlag(sn.location)|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		if sn.location == "LocalMachine" {
			return 0, fmt.Errorf(
				"could not open %s: %w. Writing to a LocalMachine store needs an elevated process — "+
					"the agent is elevated when it runs as a service and is not when it is being tried "+
					"out from an ordinary shell", sn, err)
		}
		return 0, fmt.Errorf("could not open %s: %w", sn, err)
	}
	return handle, nil
}

// importPFX puts a PKCS#12 into the store and says what it added.
func (windowsStore) importPFX(sn storeName, pfx []byte, password string) ([]string, error) {
	if len(pfx) == 0 {
		return nil, errors.New("the certificate to import is empty")
	}
	secret, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return nil, err
	}

	keyset := uint32(windows.CRYPT_MACHINE_KEYSET)
	if sn.location == "CurrentUser" {
		keyset = windows.CRYPT_USER_KEYSET
	}
	blob := windows.CryptDataBlob{Size: uint32(len(pfx)), Data: &pfx[0]}

	// No CRYPT_EXPORTABLE. See the note at the top of this file.
	staging, err := windows.PFXImportCertStore(&blob, secret,
		keyset|windows.PKCS12_ALWAYS_CNG_KSP)
	if err != nil {
		return nil, fmt.Errorf("Windows would not read the certificate: %w", err)
	}
	defer func() { _ = windows.CertCloseStore(staging, 0) }()

	// The whole PKCS#12 is read out before anything is written, so a chain that
	// cannot be parsed fails before the leaf has been installed.
	var parsed []*windows.CertContext
	if err := eachCertificate(staging, func(ctx *windows.CertContext) bool {
		parsed = append(parsed, windows.CertDuplicateCertificateContext(ctx))
		return true
	}); err != nil {
		return nil, err
	}
	defer func() {
		for _, ctx := range parsed {
			_ = windows.CertFreeCertificateContext(ctx)
		}
	}()
	if len(parsed) == 0 {
		return nil, errors.New("the certificate Windows read has nothing in it")
	}

	// Where each one belongs. The first context out of a PKCS#12 built by this
	// agent is the leaf, but that is an implementation detail of the encoder
	// and not something to rely on, so the leaf is identified by having a
	// private key rather than by its position.
	target, err := openStore(sn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CertCloseStore(target, 0) }()

	authorities := storeName{location: sn.location, name: "CA", text: sn.location + `\CA`}

	var added []string
	var roots []string
	for _, ctx := range parsed {
		der := certificateDER(ctx)
		thumb := thumbprintOf(der)
		switch {
		case hasPrivateKey(ctx):
			if err := addTo(target, ctx); err != nil {
				return added, fmt.Errorf("could not add %s to %s: %w", thumb, sn, err)
			}
			added = append(added, thumb)
		case selfSigned(ctx):
			// See the note at the top of this file: importing this would be
			// making a certificate authority trusted machine-wide, which is not
			// what installing a certificate means.
			roots = append(roots, thumb)
		default:
			ca, err := openStore(authorities)
			if err != nil {
				return added, err
			}
			err = addTo(ca, ctx)
			_ = windows.CertCloseStore(ca, 0)
			if err != nil {
				return added, fmt.Errorf(
					"could not add the intermediate %s to %s: %w. Without it schannel sends the leaf "+
						"alone, which every browser accepts from a cache and no fresh client does",
					thumb, authorities, err)
			}
			added = append(added, thumb)
		}
	}
	if len(roots) > 0 {
		// Not an error, and not silence either. Said through the log rather
		// than the install report because it is a property of the chain this
		// host was issued, identical on every renewal, and not something that
		// went wrong.
		slog.Info("a root certificate in the chain was not imported",
			"store", sn.String(), "thumbprints", strings.Join(roots, ","),
			"reason", "importing a self-signed certificate means making a certificate authority "+
				"trusted by every program on this machine, which is an administrator's decision and "+
				"not a side effect of a renewal")
	}
	return added, nil
}

// addTo copies one certificate context into a store, replacing any earlier copy
// of the same certificate along with its properties.
func addTo(store windows.Handle, ctx *windows.CertContext) error {
	return windows.CertAddCertificateContextToStore(
		store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil)
}

// thumbprintNamed reports which certificate in the store carries a friendly
// name.
func (windowsStore) thumbprintNamed(sn storeName, friendly string) (string, error) {
	store, err := openStore(sn)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	var found string
	if err := eachCertificate(store, func(ctx *windows.CertContext) bool {
		if friendlyNameOf(ctx) != friendly {
			return true
		}
		found = thumbprintOf(certificateDER(ctx))
		return false
	}); err != nil {
		return "", err
	}
	return found, nil
}

// setFriendlyName marks a certificate already in the store.
func (windowsStore) setFriendlyName(sn storeName, thumbprint, friendly string) error {
	store, err := openStore(sn)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	ctx, err := findByThumbprint(store, thumbprint)
	if err != nil {
		return err
	}
	if ctx == nil {
		return fmt.Errorf("%s holds no certificate with thumbprint %s", sn, thumbprint)
	}
	defer func() { _ = windows.CertFreeCertificateContext(ctx) }()

	encoded, err := windows.UTF16FromString(friendly)
	if err != nil {
		return err
	}
	// Bytes, including the terminating null: this property is an opaque blob to
	// CryptoAPI and the null is part of the string every reader expects.
	blob := windows.CryptDataBlob{
		Size: uint32(len(encoded) * 2),
		Data: (*byte)(unsafe.Pointer(&encoded[0])),
	}
	rc, _, err := procCertSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(certFriendlyNamePropID), 0,
		uintptr(unsafe.Pointer(&blob)))
	if rc == 0 {
		return fmt.Errorf("could not name %s in %s: %w", thumbprint, sn, err)
	}
	return nil
}

// remove deletes one certificate and the private key it points at.
//
// Not an error when it is not there: the caller asked for a store that does not
// hold this certificate, and it does not.
func (windowsStore) remove(sn storeName, thumbprint string) error {
	store, err := openStore(sn)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	ctx, err := findByThumbprint(store, thumbprint)
	if err != nil || ctx == nil {
		return err
	}

	// The key first. Once the certificate is gone there is nothing left that
	// knows which key belonged to it, and the blob would stay in the KSP for
	// the life of the machine.
	keyErr := deletePrivateKey(ctx)

	// CertDeleteCertificateFromStore frees the context whether it succeeds or
	// not, so there is no defer above and none here.
	if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
		return fmt.Errorf("could not remove %s from %s: %w", thumbprint, sn, err)
	}
	if keyErr != nil {
		return fmt.Errorf(
			"%s was removed from %s and its private key was left behind in the key storage provider: %w",
			thumbprint, sn, keyErr)
	}
	return nil
}

// deletePrivateKey removes the key a certificate points at, if it has one.
func deletePrivateKey(ctx *windows.CertContext) error {
	if !hasPrivateKey(ctx) {
		return nil
	}
	var handle windows.Handle
	var keySpec uint32
	var callerFree bool
	err := windows.CryptAcquireCertificatePrivateKey(ctx,
		windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG,
		nil, &handle, &keySpec, &callerFree)
	if err != nil {
		// A certificate whose key is already gone is the state being asked for.
		if errors.Is(err, syscall.Errno(windows.NTE_BAD_KEYSET)) ||
			errors.Is(err, syscall.Errno(windows.CRYPT_E_NO_KEY_PROPERTY)) {
			return nil
		}
		return err
	}
	if keySpec != windows.CERT_NCRYPT_KEY_SPEC {
		// Everything this agent imports is CNG, because the import forces it.
		// A legacy CSP key here belongs to a certificate somebody else put in
		// the store under this agent's name, and deleting it is not this
		// function's business.
		if callerFree {
			_, _, _ = procNCryptFreeObject.Call(uintptr(handle))
		}
		return errors.New("its private key is held by a legacy provider this agent did not create it with")
	}
	if rc, _, _ := procNCryptDeleteKey.Call(uintptr(handle), 0); rc != 0 {
		// NCryptDeleteKey frees the handle when it succeeds and not when it
		// fails, which is why this is the only branch that frees it.
		_, _, _ = procNCryptFreeObject.Call(uintptr(handle))
		return fmt.Errorf("NCryptDeleteKey returned 0x%X", rc)
	}
	return nil
}

// ── Reading a store ─────────────────────────────────────────

// eachCertificate walks a store. Returning false from fn stops the walk.
func eachCertificate(store windows.Handle, fn func(*windows.CertContext) bool) error {
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil
			}
			return fmt.Errorf("could not read the certificates in the store: %w", err)
		}
		if ctx == nil {
			return nil
		}
		if !fn(ctx) {
			// Documented as the way to stop an enumeration early. Leaving it
			// out leaks a context for the life of the process.
			_ = windows.CertFreeCertificateContext(ctx)
			return nil
		}
		prev = ctx
	}
}

// findByThumbprint returns a context the caller owns, or nil.
func findByThumbprint(store windows.Handle, thumbprint string) (*windows.CertContext, error) {
	want := strings.ToUpper(strings.TrimSpace(thumbprint))
	var found *windows.CertContext
	err := eachCertificate(store, func(ctx *windows.CertContext) bool {
		if thumbprintOf(certificateDER(ctx)) != want {
			return true
		}
		found = windows.CertDuplicateCertificateContext(ctx)
		return false
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// certificateDER copies the encoded certificate out of a context.
//
// Copied rather than aliased. The bytes belong to the context and the context
// is freed as soon as the enumeration moves on, so a slice over them is a slice
// over memory CryptoAPI has reused.
func certificateDER(ctx *windows.CertContext) []byte {
	if ctx == nil || ctx.EncodedCert == nil || ctx.Length == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)
}

// friendlyNameOf reads the display name a certificate carries, or empty.
func friendlyNameOf(ctx *windows.CertContext) string {
	var size uint32
	rc, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(certFriendlyNamePropID), 0,
		uintptr(unsafe.Pointer(&size)))
	if rc == 0 || size == 0 {
		return ""
	}
	buf := make([]byte, size)
	rc, _, _ = procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(certFriendlyNamePropID),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if rc == 0 {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0])))
}

// hasPrivateKey reports whether a certificate context names a key.
//
// CERT_KEY_PROV_INFO_PROP_ID is the property PFXImportCertStore sets on the
// certificate the key belonged to, so this is what tells the leaf from the
// intermediates without parsing anything.
func hasPrivateKey(ctx *windows.CertContext) bool {
	var size uint32
	rc, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(certKeyProvInfoPropID), 0,
		uintptr(unsafe.Pointer(&size)))
	return rc != 0 && size > 0
}

// selfSigned reports whether a certificate is its own issuer, which for the
// contents of a chain means it is the root.
func selfSigned(ctx *windows.CertContext) bool {
	cert, err := x509.ParseCertificate(certificateDER(ctx))
	if err != nil {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}
