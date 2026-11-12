package secrets

import (
	"errors"
	"testing"
)

func rotated(t *testing.T) (old, both, onlyNew *Keyring) {
	t.Helper()
	oldKey, newKey := make([]byte, KEKSize), make([]byte, KEKSize)
	for i := range oldKey {
		oldKey[i], newKey[i] = byte(i), byte(255-i)
	}
	var err error
	if old, err = NewKeyring(oldKey); err != nil {
		t.Fatal(err)
	}
	if both, err = NewKeyring(newKey, oldKey); err != nil {
		t.Fatal(err)
	}
	if onlyNew, err = NewKeyring(newKey); err != nil {
		t.Fatal(err)
	}
	return old, both, onlyNew
}

// Every envelope names the key that sealed it, and that is how a report can
// count what depends on a key without being able to open any of it.
func TestAnEnvelopeNamesTheKeyThatSealedIt(t *testing.T) {
	old, both, _ := rotated(t)

	sealed, err := old.EncryptString("secret", ContextCAAccountConfig)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := EnvelopeKeyID(sealed)
	if !ok || id != old.PrimaryKeyID() {
		t.Fatalf("EnvelopeKeyID = %q, %v; want %q", id, ok, old.PrimaryKeyID())
	}
	if id == both.PrimaryKeyID() {
		t.Fatal("the old and new keys have the same identifier")
	}

	for _, notSealed := range []string{"", "plain text", "eyJhIjoxfQ=="} {
		if id, ok := EnvelopeKeyID(notSealed); ok {
			t.Errorf("EnvelopeKeyID(%q) = %q, true; want not an envelope", notSealed, id)
		}
	}
}

// The point of re-sealing: afterwards the retired key is not needed.
func TestAResealedEnvelopeOpensWithoutTheRetiredKey(t *testing.T) {
	old, both, onlyNew := rotated(t)

	sealed, err := old.EncryptString("the CA credential", ContextCAAccountConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := onlyNew.DecryptString(sealed, ContextCAAccountConfig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("before re-sealing, the new key alone opened it or failed oddly: %v", err)
	}

	resealed, changed, err := both.Reseal(sealed, ContextCAAccountConfig)
	if err != nil || !changed {
		t.Fatalf("Reseal: changed=%v err=%v", changed, err)
	}
	got, err := onlyNew.DecryptString(resealed, ContextCAAccountConfig)
	if err != nil || got != "the CA credential" {
		t.Fatalf("after re-sealing, the new key alone read %q, %v", got, err)
	}
	if id, _ := EnvelopeKeyID(resealed); id != both.PrimaryKeyID() {
		t.Fatalf("the re-sealed envelope names key %s, not the primary %s", id, both.PrimaryKeyID())
	}
}

// Running it twice must not churn every row: a re-seal that rewrote what was
// already current could never be told apart from one that had work to do.
func TestResealLeavesWhatThePrimaryKeySealedAlone(t *testing.T) {
	_, both, _ := rotated(t)

	sealed, err := both.EncryptString("current", ContextDeploymentConfig)
	if err != nil {
		t.Fatal(err)
	}
	again, changed, err := both.Reseal(sealed, ContextDeploymentConfig)
	if err != nil || changed || again != sealed {
		t.Fatalf("Reseal rewrote a current envelope: changed=%v err=%v", changed, err)
	}
}

// A re-seal that cannot open the envelope must say so and hand nothing back,
// so a caller can never store something worse than what it had.
func TestResealRefusesWhatItCannotOpen(t *testing.T) {
	old, both, onlyNew := rotated(t)

	sealed, err := old.EncryptString("secret", ContextCAAccountConfig)
	if err != nil {
		t.Fatal(err)
	}
	if out, changed, err := onlyNew.Reseal(sealed, ContextCAAccountConfig); !errors.Is(err, ErrUnknownKey) || changed || out != "" {
		t.Errorf("without the retired key: %q, %v, %v; want ErrUnknownKey", out, changed, err)
	}
	if out, changed, err := both.Reseal(sealed, ContextDeploymentConfig); !errors.Is(err, ErrWrongContext) || changed || out != "" {
		t.Errorf("under the wrong context: %q, %v, %v; want ErrWrongContext", out, changed, err)
	}
	if out, changed, err := both.Reseal("not an envelope", ContextCAAccountConfig); !errors.Is(err, ErrMalformed) || changed || out != "" {
		t.Errorf("for a value that is not an envelope: %q, %v, %v; want ErrMalformed", out, changed, err)
	}
}
