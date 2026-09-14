package agent

// Naming the entry inside a PKCS#12 keystore.
//
// A keystore is a map, and Java looks entries up by alias. go-pkcs12's Encode
// takes no alias and writes no friendlyName attribute, so the JDK falls back to
// a counter and calls the entry "1". A Tomcat connector configured with
// certificateKeyAlias="tomcat" — which is what `keytool -genkeypair -alias
// tomcat` produces, and what most existing server.xml files carry — then cannot
// find the key. Tomcat still reports a successful startup, and this is the one
// platform with no configuration check, so nothing catches it until
// post-renewal verification notices the endpoint is serving the old
// certificate.
//
// The attribute is added after Encode rather than by forking it. go-pkcs12
// puts the key bag in an unencrypted SafeContents — only the key inside it is
// shrouded — so the attribute can be reached without touching anything the
// library encrypted. Only the MAC, which covers the whole authenticated safe,
// has to be recomputed.
//
// This does reach into a structure another package produced, and that is worth
// being uncomfortable about. Three things keep it honest: the module version is
// pinned, every claim below was checked against a real JDK, and setKeystoreAlias
// decodes its own output with the library before returning it. A layout change
// in a future version becomes a refused install rather than a keystore Java
// cannot read.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"unicode/utf16"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// PKCS#12 structures, from RFC 7292. These mirror the shapes go-pkcs12 writes,
// because this code reads back what that package produced.
type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

var (
	oidDataContentType      = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidFriendlyName         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	oidKeyBag               = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 1})
	oidPKCS8ShroundedKeyBag = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})

	oidSHA1   = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	oidSHA256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
	oidSHA512 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3})
)

// setKeystoreAlias names the private key entry in a PKCS#12 keystore.
//
// pfxData must be what pkcs12.Modern.Encode produced and password the one it
// was given, because the MAC is recomputed with it.
func setKeystoreAlias(pfxData []byte, password, alias string) ([]byte, error) {
	if alias == "" {
		return pfxData, nil
	}

	var pfx pfxPdu
	if rest, err := asn1.Unmarshal(pfxData, &pfx); err != nil {
		return nil, fmt.Errorf("the keystore just written could not be read back: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("the keystore just written has trailing data")
	}

	// The authenticated safe is an OCTET STRING holding the DER of a SEQUENCE
	// OF ContentInfo. Both layers have to come off before the bags are visible.
	var authSafeDER []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafeDER); err != nil {
		return nil, fmt.Errorf("the authenticated safe could not be read: %w", err)
	}
	var safes []contentInfo
	if _, err := asn1.Unmarshal(authSafeDER, &safes); err != nil {
		return nil, fmt.Errorf("the authenticated safe is not a sequence of ContentInfo: %w", err)
	}

	attribute, err := friendlyNameAttribute(alias)
	if err != nil {
		return nil, err
	}

	// Only the plain Data safes are searched. The certificate bags live in an
	// EncryptedData safe, and reaching into that would mean decrypting and
	// re-encrypting material this code has no reason to touch — Java takes the
	// alias from the key bag and pairs the certificate to it by localKeyId.
	named := 0
	for i, safe := range safes {
		if !safe.ContentType.Equal(oidDataContentType) {
			continue
		}
		var bagsDER []byte
		if _, err := asn1.Unmarshal(safe.Content.Bytes, &bagsDER); err != nil {
			return nil, fmt.Errorf("a safe contents could not be read: %w", err)
		}
		var bags []safeBag
		if _, err := asn1.Unmarshal(bagsDER, &bags); err != nil {
			return nil, fmt.Errorf("a safe contents is not a sequence of SafeBag: %w", err)
		}

		changed := false
		for j := range bags {
			if !bags[j].Id.Equal(oidKeyBag) && !bags[j].Id.Equal(oidPKCS8ShroundedKeyBag) {
				continue
			}
			if hasAttribute(bags[j].Attributes, oidFriendlyName) {
				return nil, errors.New(
					"the keystore already names its key entry, which this build did not expect to have written")
			}
			bags[j].Attributes = append(bags[j].Attributes, attribute)
			changed = true
			named++
		}
		if !changed {
			continue
		}

		newBagsDER, err := asn1.Marshal(bags)
		if err != nil {
			return nil, fmt.Errorf("the named bags could not be encoded: %w", err)
		}
		wrapped, err := asn1.Marshal(newBagsDER)
		if err != nil {
			return nil, fmt.Errorf("the named safe contents could not be encoded: %w", err)
		}
		safes[i].Content.Bytes = wrapped
		safes[i].Content.FullBytes = nil
	}

	if named != 1 {
		return nil, fmt.Errorf(
			"expected exactly one private key entry to name, found %d", named)
	}

	newAuthSafeDER, err := asn1.Marshal(safes)
	if err != nil {
		return nil, fmt.Errorf("the authenticated safe could not be re-encoded: %w", err)
	}
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(newAuthSafeDER); err != nil {
		return nil, fmt.Errorf("the authenticated safe could not be wrapped: %w", err)
	}
	pfx.AuthSafe.Content.FullBytes = nil

	// The MAC covers the authenticated safe, which has just changed. Without
	// this the file is intact but every reader rejects the password.
	if err := recomputeMac(&pfx.MacData, newAuthSafeDER, password); err != nil {
		return nil, err
	}

	out, err := asn1.Marshal(pfx)
	if err != nil {
		return nil, fmt.Errorf("the keystore could not be re-encoded: %w", err)
	}

	// Read it back with the library that wrote it. This is what turns a layout
	// change in a future go-pkcs12 into a failed install rather than a keystore
	// that Java cannot open — the failure would otherwise land on a host, after
	// a reload, with the old certificate already replaced.
	if _, _, _, err := pkcs12.DecodeChain(out, password); err != nil {
		return nil, fmt.Errorf(
			"naming the key entry %q produced a keystore that cannot be decoded again: %w", alias, err)
	}
	return out, nil
}

func hasAttribute(attrs []pkcs12Attribute, id asn1.ObjectIdentifier) bool {
	for _, a := range attrs {
		if a.Id.Equal(id) {
			return true
		}
	}
	return false
}

// friendlyNameAttribute builds the attribute Java reads the alias from.
func friendlyNameAttribute(alias string) (pkcs12Attribute, error) {
	encoded, err := bmpString(alias)
	if err != nil {
		return pkcs12Attribute{}, err
	}
	value, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 30, IsCompound: false, Bytes: encoded})
	if err != nil {
		return pkcs12Attribute{}, err
	}
	return pkcs12Attribute{
		Id:    oidFriendlyName,
		Value: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: value},
	}, nil
}

// bmpString encodes s as UCS-2, which is what PKCS#12 calls a BMPString.
//
// Anything outside the basic multilingual plane is refused rather than
// substituted: an alias is matched exactly against a configuration file, so a
// replacement character would produce an entry nothing can look up.
func bmpString(s string) ([]byte, error) {
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		if t, _ := utf16.EncodeRune(r); t != 0xfffd {
			return nil, fmt.Errorf(
				"alias %q contains a character that cannot be encoded in a keystore", s)
		}
		out = append(out, byte(r>>8), byte(r))
	}
	return out, nil
}

// bmpStringZeroTerminated is the form PKCS#12 passwords take.
func bmpStringZeroTerminated(s string) ([]byte, error) {
	out, err := bmpString(s)
	if err != nil {
		return nil, err
	}
	return append(out, 0, 0), nil
}

// recomputeMac replaces the MAC over a changed authenticated safe.
func recomputeMac(md *macData, message []byte, password string) error {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return err
	}

	var hFn func() hash.Hash
	var key []byte
	switch {
	case md.Mac.Algorithm.Algorithm.Equal(oidSHA256):
		hFn = sha256.New
		key = pbkdf(sha256Sum, 32, 64, md.MacSalt, encodedPassword, md.Iterations, 3, 32)
	case md.Mac.Algorithm.Algorithm.Equal(oidSHA1):
		hFn = sha1.New
		key = pbkdf(sha1Sum, 20, 64, md.MacSalt, encodedPassword, md.Iterations, 3, 20)
	case md.Mac.Algorithm.Algorithm.Equal(oidSHA512):
		hFn = sha512.New
		key = pbkdf(sha512Sum, 64, 128, md.MacSalt, encodedPassword, md.Iterations, 3, 64)
	default:
		// PBMAC1 derives its parameters differently and is what Modern2026
		// writes. Refusing here rather than guessing means moving the encoder
		// forward fails loudly in tests instead of shipping a bad MAC.
		return fmt.Errorf(
			"this build cannot recompute a %s keystore MAC", md.Mac.Algorithm.Algorithm)
	}

	mac := hmac.New(hFn, key)
	mac.Write(message)
	md.Mac.Digest = mac.Sum(nil)
	return nil
}

func sha1Sum(in []byte) []byte   { s := sha1.Sum(in); return s[:] }
func sha256Sum(in []byte) []byte { s := sha256.Sum256(in); return s[:] }
func sha512Sum(in []byte) []byte { s := sha512.Sum512(in); return s[:] }

// fillWithRepeats returns v*ceil(len(pattern)/v) bytes of pattern, repeated.
func fillWithRepeats(pattern []byte, v int) []byte {
	if len(pattern) == 0 {
		return nil
	}
	outputLen := v * ((len(pattern) + v - 1) / v)
	return bytes.Repeat(pattern, (outputLen+len(pattern)-1)/len(pattern))[:outputLen]
}

// pbkdf is the key derivation function from RFC 7292 appendix B.2.
//
// Not PBKDF2, despite the name: PKCS#12 predates it and specifies its own,
// which is why this cannot be satisfied from crypto/pbkdf2. It is here because
// the MAC key has to be derived the same way go-pkcs12 derived it, and that
// function is not exported.
//
// Correctness is not taken on trust. TestMacMatchesLibrary recomputes the MAC
// of a keystore the library just wrote and requires the bytes to be identical,
// so an error in this function fails the build rather than producing a keystore
// nothing can open.
func pbkdf(hash func([]byte) []byte, u, v int, salt, password []byte, r int, ID byte, size int) []byte {
	// D, the diversifier: v bytes of ID.
	D := bytes.Repeat([]byte{ID}, v)
	// I = S || P, each padded out to a whole number of v-byte blocks.
	S := fillWithRepeats(salt, v)
	P := fillWithRepeats(password, v)
	I := make([]byte, 0, len(S)+len(P))
	I = append(I, S...)
	I = append(I, P...)

	c := (size + u - 1) / u
	A := make([]byte, c*u)
	one := big.NewInt(1)

	for i := 0; i < c; i++ {
		// A_i = H^r(D || I)
		Ai := hash(append(append([]byte{}, D...), I...))
		for j := 1; j < r; j++ {
			Ai = hash(Ai)
		}
		copy(A[i*u:], Ai)

		if i == c-1 {
			break
		}

		// B is A_i repeated out to v bytes.
		B := make([]byte, v)
		for j := range B {
			B[j] = Ai[j%len(Ai)]
		}
		Bi := new(big.Int).SetBytes(B)

		// Each v-byte block of I becomes (block + B + 1) mod 2^(8v).
		for j := 0; j < len(I)/v; j++ {
			block := new(big.Int).SetBytes(I[j*v : (j+1)*v])
			block.Add(block, Bi)
			block.Add(block, one)
			b := block.Bytes()
			if len(b) > v {
				b = b[len(b)-v:] // the mod 2^(8v)
			}
			dst := I[j*v : (j+1)*v]
			for k := range dst {
				dst[k] = 0
			}
			copy(dst[v-len(b):], b)
		}
	}

	return A[:size]
}
