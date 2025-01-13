package trust // import "github.com/docker/docker/daemon/trust"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/distribution/reference"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/theupdateframework/notary/tuf/data"
	"gotest.tools/v3/assert"
)

// Hard to test the service without a bunch of servers and auth set up, but
// we can test the cache functionality and the trustpinning/official image
// override

// This is hardcoded metadata from docker.io/library/alpine - have to ignore
// expiry because the timestamp expires every 2 weeks and needs to be re-signed
var alpineMeta = map[data.RoleName][]byte{
	data.CanonicalTimestampRole: []byte(`{"signed":{"_type":"Timestamp","expires":"2018-08-03T15:48:41.776179945Z","meta":{"snapshot":{"hashes":{"sha256":"ZUkaNVCtSi33iEjy/sHNIn+uM1CrvRtxsnHa8ykSvvg=","sha512":"q/kBH4STz+lho3j2gS1+p1HjImXMdaarw+2xIKxFRzNTMyt0eO5u1p2D1Vlykv7jLipbiIdOxilCYRIFHLbhaA=="},"length":686}},"version":383},"signatures":[{"keyid":"628b0c4ec148075104e8ba30625aba7461754bd4f08ace05746b75f8c04395e8","method":"ecdsa","sig":"rLmG6WJn+3ODBIavSZoHFZaIbfU8YnTmAbfdR/NoeRCBZAhuz8BN1krJpXw4MNx0Qq1C030BfOa17A46QQXxPQ=="}]}`),
	data.CanonicalSnapshotRole:  []byte(`{"signed":{"_type":"Snapshot","expires":"2021-07-05T15:40:33.084061135Z","meta":{"root":{"hashes":{"sha256":"4zpZyn6xnZulVL6qps/z2qUcQTz5dwE5N5UU2FJqt6k=","sha512":"4aWG1SpgmnbbjhJlT7n1M9ZHwbXcnxlyfufiykSTEC2JHAAh2jKq8h3BvukmYq+62JN5N3pC3edBvady6aFejA=="},"length":2390},"targets":{"hashes":{"sha256":"KJnHU9EZAvPTkEjT+pR6QIH68Lfhv10lBHjvzHnVbEg=","sha512":"WRu8VAEMlOPfmoAtP0QYOgcC1fUlFDm4LQXoIDIZ0/Z6lzDVlO8IZyxn9tAF+5c8wsCIybHhSolEgeYBLn3VYQ=="},"length":1508}},"version":331},"signatures":[{"keyid":"0c14a4976e6762dca610cbe3e5ff8e72bafa62853bc1212f71236dccab6b33c7","method":"ecdsa","sig":"fTX36DifY/Y5L4meJTUkiNfW0ke6B1mU80UP3d6ktx4ATeTHPQiwKfxhGaf6svZgM4PtZEPSQNlMqGBtfypJyQ=="}]}`),
	data.CanonicalRootRole:      []byte(`{"signed":{"_type":"Root","consistent_snapshot":false,"expires":"2025-08-07T20:36:33.117452-07:00","keys":{"0c14a4976e6762dca610cbe3e5ff8e72bafa62853bc1212f71236dccab6b33c7":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJOD10PVznbeIdXUme2K7JDUBBwQoQpkKRiifqyfvdRsWvED11qJ3Z3jVKO/uiTVDgMSYxdK/IYZ8JxngnPvmLg=="}},"5a46c9aaa82ff150bb7305a2d17d0c521c2d784246807b2dc611f436a69041fd":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGprzelK+4dae+xeJJkT96BTlCDXlsO8x8VKWwMpgjkwi+8XeYuRtWlRHFSYMd3EudrPm5Xa4NGE44eRKnoG2eA=="}},"628b0c4ec148075104e8ba30625aba7461754bd4f08ace05746b75f8c04395e8":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2ACIDBRD/hSEayT3AbzWcjaX3turZJS7ChrBWGfZjqyDgnfIEo2ZtzEft1PrAO7+5qWcQk/7r6QbnOb9tyacDw=="}},"a2489bcac7a79aa67b19b96c4a3bf0c675ffdf00c6d2fabe1a5df1115e80adce":{"keytype":"ecdsa-x509","keyval":{"private":null,"public":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJlVENDQVNDZ0F3SUJBZ0lSQUpGYlBTR2RIQ3NsTzFEV1I5aTg0NDB3Q2dZSUtvWkl6ajBFQXdJd0l6RWgKTUI4R0ExVUVBeE1ZWkc5amEyVnlMbWx2TDJ4cFluSmhjbmt2WVd4d2FXNWxNQjRYRFRFMU1EZ3hNVEF6TXpZegpNbG9YRFRJMU1EZ3dPREF6TXpZek1sb3dJekVoTUI4R0ExVUVBeE1ZWkc5amEyVnlMbWx2TDJ4cFluSmhjbmt2CllXeHdhVzVsTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFT1hZdGE1VGdkQ3dYVENuTFUwOVcKNVQ0TTRyOWZRUXJxSnVBRFA2VTdnNXI5SUNnUFNtWnVSSFAvMUFZVWZPUVczYmF2ZUtzVDk2OUVmRUxLajFsZgpDS00xTURNd0RnWURWUjBQQVFIL0JBUURBZ0NnTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNRE1Bd0dBMVVkCkV3RUIvd1FDTUFBd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ1lyUUpMdTJNZmFwa3NqUlUySHR3dnoxcEhWalMKLzNHRllJRXVYNXA4ZktNQ0lBazJFdlVpWCtVTDJPanppZTQvcDlJYlppWWRvMFdVcTdITkpmN2hyc0NyCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"}}},"roles":{"root":{"keyids":["a2489bcac7a79aa67b19b96c4a3bf0c675ffdf00c6d2fabe1a5df1115e80adce"],"threshold":1},"snapshot":{"keyids":["0c14a4976e6762dca610cbe3e5ff8e72bafa62853bc1212f71236dccab6b33c7"],"threshold":1},"targets":{"keyids":["5a46c9aaa82ff150bb7305a2d17d0c521c2d784246807b2dc611f436a69041fd"],"threshold":1},"timestamp":{"keyids":["628b0c4ec148075104e8ba30625aba7461754bd4f08ace05746b75f8c04395e8"],"threshold":1}},"version":1},"signatures":[{"keyid":"a2489bcac7a79aa67b19b96c4a3bf0c675ffdf00c6d2fabe1a5df1115e80adce","method":"ecdsa","sig":"q/KOmzsd+Q2hE4fHtp5Fq6441X99GHDaFmCtFcKjSE4LVuN1qxcyPBpxRg0H8FOwxhyYvmbdkYem0LFXmBdFOQ=="}]}`),
	data.CanonicalTargetsRole:   []byte(`{"signed":{"_type":"Targets","delegations":{"keys":{},"roles":[]},"expires":"2021-07-05T15:40:33.083677397Z","targets":{"2.6":{"hashes":{"sha256":"ms5VFhMHBomhKFfWLDDvDaqaN2EH7A//DjR4bO2zOZs="},"length":528},"2.7":{"hashes":{"sha256":"nwgAXf9VIDjwrS9GuOZf89JWQXR9ORLj6o2meFBGVho="},"length":1374},"3.1":{"hashes":{"sha256":"L536at9gLT1zefEfPU/Qt7TRxSZhbufA/V5VOnLkv3k="},"length":433},"3.2":{"hashes":{"sha256":"SwLSdFGqvfK2vNCYiN7tVrKjtkWqs7d7yVEc+A0IIKY="},"length":433},"3.3":{"hashes":{"sha256":"N/TXuzUr3lh5fQ8MTmxOaantRNTkeoq0RhiI0RfRTGo="},"length":433},"3.4":{"hashes":{"sha256":"waoPk9EyWNyLToc5HwJDLcIUc2w/F24uQzYpwq/paqA="},"length":433},"3.5":{"hashes":{"sha256":"TT7GMc3emKA7kUd7QRoftCqcrdgTnC54Ap5E4ZnlhDM="},"length":433},"3.6":{"hashes":{"sha256":"3lcB1qOjbcal2yYNIb4EIv0w3S0VjB4EizQmPnMgXLY="},"length":2029},"3.7":{"hashes":{"sha256":"VuL5HvFYR6KwKloDy/pIOUnWeiQsN+M+oXjj5+AeDf0="},"length":2029},"3.8":{"hashes":{"sha256":"cEMHY0i/UEAiDfatcDeY/YWToJGNBtPOMMbJO+EX5DA="},"length":2029},"edge":{"hashes":{"sha256":"jZhyv33JRtsbPNK/cHUvWQhew8UDXKHYINMPHRJn1l0="},"length":2029},"integ-test-base":{"hashes":{"sha256":"OVLcSNzEE2zN3jf7734lA0ZTilWgNm4/zMaDM2N343I="},"length":528},"latest":{"hashes":{"sha256":"cEMHY0i/UEAiDfatcDeY/YWToJGNBtPOMMbJO+EX5DA="},"length":2029}},"version":323},"signatures":[{"keyid":"5a46c9aaa82ff150bb7305a2d17d0c521c2d784246807b2dc611f436a69041fd","method":"ecdsa","sig":"9VhXUheb+gNBfHakog51WV7HXN46BltvJDfn8HLp9h1YxqFIY2WmqJtrQ9UNfXIcTiSXzLL0XlPZjE+WKYlqrg=="}]}`),
}

// fake service to be used to break out of actually pinging the default notary service
// during unit tests
type fakeService struct {
	RegistryService
	repoInfo *registry.RepositoryInfo
	err      error
}

func (s *fakeService) ResolveRepository(ref reference.Named) (*registry.RepositoryInfo, error) {
	return s.repoInfo, s.err
}

// Tests that if the server is unreachable service can load trust data from cache
func TestServiceLoadsFromCache(t *testing.T) {
	tmpDir := t.TempDir()

	// make sure we have a cache
	imageDir := filepath.Join(tmpDir, "docker.io", "library", "alpine")
	assert.NilError(t, os.MkdirAll(imageDir, 0755))
	for role, metaBytes := range alpineMeta {
		assert.NilError(t, os.WriteFile(filepath.Join(imageDir, role.String()+".json"), metaBytes, 0644))
	}

	alpineRef, err := reference.WithName("docker.io/library/alpine")
	assert.NilError(t, err)

	s := Service{
		TrustCachePath: tmpDir,
		RegistryService: &fakeService{
			err: errors.New("fake registry error"),
		},
	}
	ref, err := s.VerifyImageSigned(context.Background(), &config.ContentTrust{AllowExpiredCachedTrustData: true}, alpineRef, nil, nil)
	assert.NilError(t, err)
	assert.Assert(t, ref != nil)
}

// Tests that the official root keys are used to validate official images by default,
// and that metadata can be read from cache.
func TestServicePinsOfficialRootKeys(t *testing.T) {
	tmpDir := t.TempDir()

	alpineRef, err := reference.WithName("docker.io/library/alpine")
	assert.NilError(t, err)

	// run a little server that serves up the alpine metadata
	mux := http.NewServeMux()
	for role, metaBytes := range alpineMeta {
		fmt.Println(role.String())
		// notary will request /v2/docker.com/library/alpine/_trust/tuf/<role>.json
		// and /v2/docker.com/library/alpine/_trust/tuf/<role>.<sha256hash>.json
		// for snapshot, root, and targets roles
		getWriter := func(toWrite []byte) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Write(toWrite)
			}
		}
		mux.HandleFunc(
			fmt.Sprintf("/v2/docker.io/library/alpine/_trust/tuf/%s.json", role),
			getWriter(metaBytes))
		if role == data.CanonicalTimestampRole {
			continue
		}
		// rather than parse all the notary metadata, just shasum it ourselves
		shasum := sha256.Sum256(metaBytes)
		hexSum := hex.EncodeToString(shasum[:])
		mux.HandleFunc(
			fmt.Sprintf("/v2/docker.io/library/alpine/_trust/tuf/%s.%s.json", role, hexSum),
			getWriter(metaBytes))
	}
	testServer := httptest.NewServer(mux)
	u, err := url.Parse(testServer.URL)
	assert.NilError(t, err)

	rService, err := registry.NewService(registry.ServiceOptions{})
	assert.NilError(t, err)

	fake := &fakeService{
		RegistryService: rService,
		repoInfo: &registry.RepositoryInfo{
			// don't specify Official: true so we don't default to using the default trust server
			Name: alpineRef,
			Index: &registrytypes.IndexInfo{
				Name: u.Host,
			},
			Class: "image",
		},
	}

	s := Service{
		TrustCachePath:  tmpDir,
		RegistryService: fake,
	}

	assertTrustFail := func(cfg *config.ContentTrust) {
		t.Helper()
		_, err = s.VerifyImageSigned(context.Background(), cfg, alpineRef, nil, nil)
		assert.ErrorContains(t, err, "could not validate the path to a trusted root")
	}

	assertTrustSuccess := func(cfg *config.ContentTrust) {
		t.Helper()
		// Unfortunately this still errors because the because the above hardcoded info is expired,
		// but it will not fail with a trust error at least
		_, err = s.VerifyImageSigned(context.Background(), cfg, alpineRef, nil, nil)
		assert.ErrorContains(t, err, "expired at")
	}

	// If we don't specify TrustOfficialLibraryImages: true, the image verify should fail due to pinning
	assertTrustFail(&config.ContentTrust{
		AllowExpiredCachedTrustData: true,
	})

	// If we specify TrustOfficialLibraryImages, we can download
	assertTrustSuccess(&config.ContentTrust{
		AllowExpiredCachedTrustData: true,
		TrustPinning: config.TrustPinning{
			OfficialLibraryImages: true,
		},
	})

	// User specified keys overwrite the docker official library pinned keys
	// if they are at least equally as specific
	assertTrustFail(
		&config.ContentTrust{
			AllowExpiredCachedTrustData: true,
			TrustPinning: config.TrustPinning{
				OfficialLibraryImages: true,
				RootKeys: map[string][]string{
					"docker.io/library/*": {"abcd"},
				},
			},
		})

	// User specified keys don't overwrite the docker official library pinned keys
	// if they are less specific
	assertTrustSuccess(&config.ContentTrust{
		AllowExpiredCachedTrustData: true,
		TrustPinning: config.TrustPinning{
			OfficialLibraryImages: true,
			RootKeys: map[string][]string{
				"docker.io/*": {"abcd"},
			},
		},
	})
}
