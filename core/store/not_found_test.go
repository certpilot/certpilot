package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A missing record and a failed read used to be indistinguishable: every
// lookup by id said "… not found" as plain text, so the API answered 404 for
// both. A v0.2.1 core started on an unmigrated database answered 404 for a
// certificate that existed, because its query failed on a missing column (#135).
//
// Lookups split into two conventions, and each method has to be in one of them.

// byIDMethods return ErrNotFound, and nothing else, for a record that does not
// exist.
var byIDMethods = []string{
	"GetAgent", "GetCAAccount", "GetCAAuthority", "GetCTMonitor", "GetCertificate",
	"GetCertificateDeployment", "GetCertificatePrivateKey", "GetCertificateTemplate",
	"GetCertificateTemplateBySlug", "GetCloudCertificate", "GetCloudConnection",
	"GetDeploymentJob", "GetDeploymentTarget", "GetDiscoveryResult", "GetDiscoveryScan",
	"GetDiscoverySchedule", "GetDisplayTokenByHash", "GetMetadataField",
	"GetNotificationChannel", "GetPolicy", "GetRenewalJob", "GetTemplateGrant",
}

// lookupMethods answer a miss with a nil or empty result and a nil error. Their
// callers ask "is there one?", and a miss is an ordinary answer to that.
var lookupMethods = []string{
	"GetAgentEnrolTokenByHash", "GetCAAuthorityByFingerprint", "GetCAChain",
	"GetCertificateByFingerprint", "GetCertificateBySupersededFingerprint",
	"GetGrantsForAgent", "GetUser",
}

const missingID = "6f9d0f6e-0000-4000-8000-000000000000"

// TestEveryLookupFollowsItsConventionConformance.
func TestEveryLookupFollowsItsConventionConformance(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		v := reflect.ValueOf(s)
		byID := set(byIDMethods)
		lookup := set(lookupMethods)

		var unclassified []string
		for _, name := range singleKeyGets(v) {
			out := v.MethodByName(name).Call([]reflect.Value{
				reflect.ValueOf(context.Background()), reflect.ValueOf(missingID),
			})
			err, _ := out[1].Interface().(error)
			empty := isEmpty(out[0])

			switch {
			case byID[name]:
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("%s: a missing record returned %v, want an error wrapping ErrNotFound", name, err)
				}
				if !empty {
					t.Errorf("%s: a missing record returned a non-empty result alongside its error", name)
				}
			case lookup[name]:
				if err != nil || !empty {
					t.Errorf("%s: a miss returned (%v, %v), want an empty result and no error", name, out[0], err)
				}
			default:
				unclassified = append(unclassified, name)
			}
		}
		if len(unclassified) > 0 {
			t.Errorf("Get methods in neither byIDMethods nor lookupMethods: %s. "+
				"Decide which convention each follows and add it", strings.Join(unclassified, ", "))
		}
	})
}

// singleKeyGets lists every Get method that takes a context and one string.
func singleKeyGets(v reflect.Value) []string {
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	var names []string
	for i := 0; i < v.NumMethod(); i++ {
		m := v.Type().Method(i)
		ft := m.Type
		if strings.HasPrefix(m.Name, "Get") && ft.NumIn() == 3 && ft.In(1).Implements(ctxType) &&
			ft.In(2).Kind() == reflect.String && ft.NumOut() == 2 {
			names = append(names, m.Name)
		}
	}
	sort.Strings(names)
	return names
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map:
		return v.IsNil()
	case reflect.Slice:
		return v.Len() == 0
	case reflect.String:
		return v.String() == ""
	}
	return false
}

func set(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
