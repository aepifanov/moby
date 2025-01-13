package trust // import "github.com/docker/docker/daemon/trust"

import (
	"bytes"
	"testing"

	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
	"github.com/theupdateframework/notary/tuf/testutils"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

var (
	unexpiredMeta, expiredMeta map[data.RoleName][]byte
	metaKeys                   signed.CryptoService
	namedRef                   reference.Named
	rootKeyID                  string
	imageDigests               map[string]digest.Digest
)

// Creates a repo with "latest", "v1", and "v2"
func setup(t *testing.T) {
	t.Helper()
	if unexpiredMeta != nil {
		return
	}
	repo, cs, err := testutils.EmptyRepo("docker.io/trust", releasesRole, "targets/hello")
	assert.NilError(t, err)
	metaKeys = cs

	targets := make(data.Files)
	imageDigests = make(map[string]digest.Digest)
	for _, tgt := range []string{"latest", "v1", "v2"} {
		fileMeta, err := data.NewFileMeta(bytes.NewBuffer([]byte(tgt)), notary.SHA256)
		assert.NilError(t, err)
		targets[tgt] = fileMeta
		imageDigests[tgt] = digest.NewDigestFromBytes(
			digest.SHA256, fileMeta.Hashes[notary.SHA256])
	}
	_, err = repo.AddTargets(releasesRole, targets)
	assert.NilError(t, err)

	unexpiredMeta, err = testutils.SignAndSerialize(repo)
	assert.NilError(t, err)

	swizz := testutils.NewMetadataSwizzler("docker.io/trust", unexpiredMeta, cs)
	err = swizz.ExpireMetadata(data.CanonicalTimestampRole)
	assert.NilError(t, err)

	ts, err := swizz.MetadataCache.GetSized("timestamp", storage.NoSizeLimit)
	assert.NilError(t, err)

	expiredMeta = make(map[data.RoleName][]byte)
	for role, val := range unexpiredMeta {
		if role == data.CanonicalTimestampRole {
			expiredMeta[role] = ts
		} else {
			expiredMeta[role] = val
		}
	}

	namedRef, err = reference.WithName("docker.io/trust")
	assert.NilError(t, err)

	keys := cs.ListKeys(data.CanonicalRootRole)
	assert.Assert(t, is.Len(keys, 1))
	rootKeyID = keys[0]
}

// ---- fake remote server that servers metadata

type fakeRemote struct {
	storage.MetadataStore
}

func (f fakeRemote) GetKey(role data.RoleName) ([]byte, error) {
	return nil, errors.New("unimplemented")
}
func (f fakeRemote) RotateKey(role data.RoleName) ([]byte, error) {
	return nil, errors.New("unimplemented")
}

type failedRemote struct {
	fakeRemote
}

func (f failedRemote) GetSized(name string, size int64) ([]byte, error) {
	return nil, storage.NetworkError{Wrapped: errors.New("fake server fail")}
}

type partialFailedRemote struct {
	fakeRemote
	counter int
}

func (f *partialFailedRemote) GetSized(name string, size int64) ([]byte, error) {
	if f.counter > 2 {
		return nil, storage.NetworkError{Wrapped: errors.New("fake server fail")}
	}
	f.counter++
	return f.fakeRemote.GetSized(name, size)
}

// --------- Tests begin ---------

func TestCopyCache(t *testing.T) {
	from := storage.NewMemoryStore(unexpiredMeta)
	to := storage.NewMemoryStore(nil)

	assert.NilError(t, copyCache(from, to))
	assert.Equal(t, len(to.ListFiles()), len(unexpiredMeta))
	for role, val := range unexpiredMeta {
		got, err := to.Get(role.String())
		assert.NilError(t, err)
		assert.DeepEqual(t, val, got)
	}
}

func TestVerifyImageExpiredMetadata(t *testing.T) {
	setup(t)

	// If the server is available, and the metadata is expired, VerifyImage will error whether or not the
	// ignoreExpiry bool is set, even if there is already perfectly valid metadata in the cache
	for _, ignoreExpiry := range []bool{true, false} {
		v := &verifier{
			cache:        storage.NewMemoryStore(unexpiredMeta),
			keyIDs:       map[string][]string{"*": {rootKeyID}},
			ignoreExpiry: ignoreExpiry,
		}
		_, err := v.VerifyImage(namedRef, fakeRemote{
			MetadataStore: storage.NewMemoryStore(expiredMeta)})
		assert.ErrorContains(t, err, "timestamp expired at")
	}

	// If the server is unavailable, and the cached metadata is expired, VerifyImage will error only if
	// ignoreExpriy is not set to true
	v := &verifier{
		cache:  storage.NewMemoryStore(expiredMeta),
		keyIDs: map[string][]string{"*": {rootKeyID}},
	}
	_, err := v.VerifyImage(namedRef, failedRemote{})
	assert.ErrorContains(t, err, "fake server fail")

	v.ignoreExpiry = true
	ref, err := v.VerifyImage(namedRef, failedRemote{})
	assert.NilError(t, err)
	assert.Equal(t, imageDigests["latest"], ref.Digest())
}

func TestVerifyImageRefResolution(t *testing.T) {
	setup(t)

	v := &verifier{
		cache:  storage.NewMemoryStore(nil),
		keyIDs: map[string][]string{"*": {rootKeyID}},
	}

	remote := fakeRemote{MetadataStore: storage.NewMemoryStore(unexpiredMeta)}

	checkRef := func(r reference.Named, tag string) {
		ref, err := v.VerifyImage(r, remote)
		assert.NilError(t, err)
		assert.Equal(t, "docker.io/trust", ref.Name())
		tagged, ok := ref.(reference.NamedTagged)
		assert.Assert(t, ok)
		assert.Equal(t, tag, tagged.Tag())
		assert.Equal(t, imageDigests[tag], ref.Digest())
	}

	// if neither tag nor digest is passed, "latest" is the tag and the digest
	// is expected
	checkRef(namedRef, "latest")

	// if only a tag is passed, it is used to resolve the digest
	tagged, err := reference.WithTag(namedRef, "v1")
	assert.NilError(t, err)
	checkRef(tagged, "v1")

	// if only a digest is passed, it is used to do a reverse lookup of the tag
	digested, err := reference.WithDigest(namedRef, imageDigests["v2"])
	assert.NilError(t, err)
	checkRef(digested, "v2")

	// if both a digest is passed, the tag and digest are verified
	taggedAndDigested, err := reference.WithTag(digested, "v2")
	assert.NilError(t, err)
	checkRef(taggedAndDigested, "v2")

	badTag, err := reference.WithTag(digested, "v1")
	assert.NilError(t, err)
	_, err = v.VerifyImage(badTag, remote)
	assert.ErrorContains(t, err, "does not match provided digest")

	// if no tag was found, the image cannot be resolved
	badTag, err = reference.WithTag(namedRef, "v3")
	assert.NilError(t, err)
	_, err = v.VerifyImage(badTag, remote)
	assert.ErrorContains(t, err, "no trust signature found")
}

func TestVerifyImageCacheManagement(t *testing.T) {
	setup(t)

	v := &verifier{
		cache:  storage.NewMemoryStore(nil),
		keyIDs: map[string][]string{"*": {rootKeyID}},
	}

	remote := fakeRemote{MetadataStore: storage.NewMemoryStore(unexpiredMeta)}

	// If the download fails halfway through an update, the cache will not
	// be altered
	_, err := v.VerifyImage(namedRef, &partialFailedRemote{fakeRemote: remote})
	assert.ErrorContains(t, err, "fake server fail")
	assert.Equal(t, len(v.cache.ListFiles()), 0)

	// If the download succeeds, the cache will be updated
	_, err = v.VerifyImage(namedRef, remote)
	assert.NilError(t, err)
	// Length is greater because the cache writes not only the files themselves
	assert.Assert(t, len(v.cache.ListFiles()) > len(unexpiredMeta))
	for role, val := range unexpiredMeta {
		got, err := v.cache.GetSized(role.String(), storage.NoSizeLimit)
		assert.NilError(t, err)
		assert.DeepEqual(t, val, got)
	}

	// The cache is used to verify the download (e.g. if the cache's versions were
	// higher than the server's), the download fails, and the cache will not have
	// been overwritten
	swizz := testutils.NewMetadataSwizzler(data.GUN("docker.io/trust"), unexpiredMeta, metaKeys)
	assert.NilError(t, swizz.OffsetMetadataVersion(data.CanonicalTimestampRole, 2))

	newMeta := make(map[data.RoleName][]byte)
	for role, val := range unexpiredMeta {
		newMeta[role] = val
		if role == data.CanonicalTimestampRole {
			newMeta[role], err = swizz.MetadataCache.GetSized(
				data.CanonicalTimestampRole.String(), storage.NoSizeLimit)
			assert.NilError(t, err)
		}
	}

	v.cache = storage.NewMemoryStore(newMeta)
	_, err = v.VerifyImage(namedRef, remote)
	assert.ErrorContains(t, err, "trust data version is lower than expected")

	for role, val := range newMeta {
		got, err := v.cache.GetSized(role.String(), storage.NoSizeLimit)
		assert.NilError(t, err)
		assert.DeepEqual(t, val, got)
	}
}

func TestVerifyImageTrustPinning(t *testing.T) {
	setup(t)

	remote := fakeRemote{MetadataStore: storage.NewMemoryStore(unexpiredMeta)}

	v := &verifier{
		cache: storage.NewMemoryStore(nil),
	}

	for _, invalidKeyPinning := range []map[string][]string{
		nil,                           // no pinned keys
		make(map[string][]string),     // empty pinned keys
		{"docker.com/*": {rootKeyID}}, // key pinned to wrong gun
		{"docker.io/*": {"hello"}},    // wrong key pinned to gun
		{ // wrong key pinned most precise gun
			"docker.io/*":     {rootKeyID},
			"docker.io/trust": {"hello"},
		},
	} {
		v.keyIDs = invalidKeyPinning
		_, err := v.VerifyImage(namedRef, remote)
		assert.ErrorContains(t, err, "could not validate the path to a trusted root")
	}

	// correct key correctly downloads, even if there are other incorrect keys
	v.keyIDs = map[string][]string{"docker.io/*": {rootKeyID, "hello"}}
	_, err := v.VerifyImage(namedRef, remote)
	assert.NilError(t, err)
}

func TestVerifyImageWorksWithOfflineStore(t *testing.T) {
	setup(t)

	v := &verifier{
		cache: storage.NewMemoryStore(unexpiredMeta),
	}

	ref, err := v.VerifyImage(namedRef, nil)
	assert.NilError(t, err)
	assert.Equal(t, "docker.io/trust", ref.Name())
	tagged, ok := ref.(reference.NamedTagged)
	assert.Assert(t, ok)
	assert.Equal(t, "latest", tagged.Tag())
	assert.Equal(t, imageDigests["latest"], ref.Digest())
}
