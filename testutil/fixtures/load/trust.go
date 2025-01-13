package load // import "github.com/docker/docker/testutil/fixtures/load"
import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var trustImages = map[string]string{
	"dockertrusttest.docker.io/library/busybox:latest": "busybox:latest@sha256:bbc3a03235220b170ba48a157dd097dd1379299370e1ed99ce976df0355d24f0",
}

// XXXXXX the root key ID for this trust data is 42d0661a0cd7fff32ca7fe7a6760a077792c8eb1a7f2a9a1115bea71c8b1d82d

var trustDataBad = map[string][]byte{
	"timestamp.json": []byte(`{"signed":{"_type":"Timestamp","expires":"2018-09-03T20:37:34.5545169Z","meta":{"snapshot":{"hashes":{"sha256":"VpCMVoPM88UlX/ipKorCWYN1ZPDLMllaks4LqNcelts=","sha512":"eQiTgbXvD0dESPaTa0ZpqCKa/neOUdIXsbE0kN/wPaOq3cRPY2xuMeJySa7cDA5ET32TmQzrldGAckH9bQyHsw=="},"length":688}},"version":1},"signatures":[{"keyid":"57f4be2f6064065abcd6b7cb44c7008e10f5740584a375cc138ee59ab9cc4e1a","method":"ecdsa","sig":"D5RqEzVImJCuADjpV4F8OkGey42EQv7PQKc+fFkJ1klrYd41IhjkWOgIc0diwqVQpM0ALbe8SKPWPYvIVl/DHQ=="}]}`),
	"snapshot.json":  []byte(`{"signed":{"_type":"Snapshot","expires":"2021-08-19T13:37:33.148179683-07:00","meta":{"root":{"hashes":{"sha256":"dHeOIluK5H2NPmL5MAUnjdg1TiV9Assu+kBkRbnudgg=","sha512":"1OFkGNkgHDz+rMW+9GHyzvqIKSOO+b9G/+8LRBtfo0kDI8qTauKp2DOYRypGQz3tFqT98mSyIDIHkN6dqltBuA=="},"length":2461},"targets":{"hashes":{"sha256":"GogMtdLxKhf6AQtDsJ8j3ZOP5rN1wByoFUEbVhn0qzM=","sha512":"3cX0o5Jm5yR0+HU3W2NpetCSIaGLbU1PAfgVV8J9+Po4emPZwJOFGbT1ep7YSFF7WHTic/QUdjAR6OerPIEi0Q=="},"length":526}},"version":2},"signatures":[{"keyid":"04b15fa43c0a71d6bb6efb8a11326ca6f5cdcdaf0ef0e1112fbabfa999db13c9","method":"ecdsa","sig":"giIu2NoO1Ab+OrYs/S7wmDA251tmOHWsmviO1RdeceNhhh+nmMioqIcr8MqxggUCcUvp4VrCdJMIpJwdn/Vo1w=="}]}`),
	"targets.json":   []byte(`{"signed":{"_type":"Targets","delegations":{"keys":{},"roles":[]},"expires":"2021-08-19T13:37:33.147145795-07:00","targets":{"glibc":{"hashes":{"sha256":"C1WjA5QpSrI7mv1Y+rlOYakj9YNPun3brn+ODBG6heY="},"length":528},"latest":{"hashes":{"sha256":"u8OgMjUiCxcLpIoVfdCX3RN5KZNw4e2Zzpdt8DVdJPA="},"length":527}},"version":2},"signatures":[{"keyid":"59f2ac3f089dc82a3cbf5a4cfa3690ddb6d9327c7ab59913027e7e38f4be7b20","method":"ecdsa","sig":"G6ZaBzqJB7HVD8abnJKR8ZtYP6LsoTySAXZZKY7nvCQUYAOw/ojuo6ShtHICijcgGA7xkCrNOMWDPSGfE5KmrA=="}]}`),
	"root.json":      []byte(`{"signed":{"_type":"Root","consistent_snapshot":false,"expires":"2028-08-17T12:05:00.722230121-07:00","keys":{"04b15fa43c0a71d6bb6efb8a11326ca6f5cdcdaf0ef0e1112fbabfa999db13c9":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWS/GqbgnoisGsRKNG+/7LTxtMrn8v6G6KZQ0Ol4fJKP6jKHcshRYph+MGrCY3QmwqrkOL5w7MLlcHyaP45PbWA=="}},"57f4be2f6064065abcd6b7cb44c7008e10f5740584a375cc138ee59ab9cc4e1a":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9G60ATqbIOxTe85U51g0vOkQVXwXh7puqV+6SW8DCzLQXX8omAvYuVgioXYOatjPQ6uyvNQaueQQ8/pdcku4cg=="}},"59f2ac3f089dc82a3cbf5a4cfa3690ddb6d9327c7ab59913027e7e38f4be7b20":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExD16yXfDX8eym3NRlWKrzhMvQx+199to2mZ5PSc00ySILXZk2BIR0ixGthfAaRf6Gx720bPT4lJrXsa74FCXtg=="}},"81ec8b1d071770345d243c0f96e1d4b8039f15e29d418f17d0a6c0c01204aee9":{"keytype":"ecdsa-x509","keyval":{"private":null,"public":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJtekNDQVVHZ0F3SUJBZ0lRQ1ZWV01JNmY4SHFuYVdjRnpINzdlVEFLQmdncWhrak9QUVFEQWpBME1USXcKTUFZRFZRUURFeWxrYjJOclpYSjBjblZ6ZEhSbGMzUXVaRzlqYTJWeUxtbHZMMnhwWW5KaGNua3ZZblZ6ZVdKdgplREFlRncweE9EQTRNakF4T1RBME5UWmFGdzB5T0RBNE1UY3hPVEEwTlRaYU1EUXhNakF3QmdOVkJBTVRLV1J2ClkydGxjblJ5ZFhOMGRHVnpkQzVrYjJOclpYSXVhVzh2YkdsaWNtRnllUzlpZFhONVltOTRNRmt3RXdZSEtvWkkKemowQ0FRWUlLb1pJemowREFRY0RRZ0FFVmtsUjFsYzNmRFc4c08wMUpRRGxjYlFMYUN2MDk2UC9FNzAxWDNUbQpxdHdVL0VUQlM3RjRPMTJYVWpoeERjd0NNNWl0NlhBQStnM0k1engrMVRXQ2Y2TTFNRE13RGdZRFZSMFBBUUgvCkJBUURBZ1dnTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNRE1Bd0dBMVVkRXdFQi93UUNNQUF3Q2dZSUtvWkkKemowRUF3SURTQUF3UlFJZ1VHWmVDYlNPQzI4OVpLbi9GMjJ1bmdxUFA2UGZNWVc4b0ZjVGMrTVhVaHdDSVFDcgp1NVlNSjhmZUJqTlFEVEtSVEY3UVI3OWgxNEJQTFp1TVhnMVg4dXgxRHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="}}},"roles":{"root":{"keyids":["81ec8b1d071770345d243c0f96e1d4b8039f15e29d418f17d0a6c0c01204aee9"],"threshold":1},"snapshot":{"keyids":["04b15fa43c0a71d6bb6efb8a11326ca6f5cdcdaf0ef0e1112fbabfa999db13c9"],"threshold":1},"targets":{"keyids":["59f2ac3f089dc82a3cbf5a4cfa3690ddb6d9327c7ab59913027e7e38f4be7b20"],"threshold":1},"timestamp":{"keyids":["57f4be2f6064065abcd6b7cb44c7008e10f5740584a375cc138ee59ab9cc4e1a"],"threshold":1}},"version":1},"signatures":[{"keyid":"81ec8b1d071770345d243c0f96e1d4b8039f15e29d418f17d0a6c0c01204aee9","method":"ecdsa","sig":"1Tc67fkqwJvZ7zOJfBg530RvJ+qbrywLc36aoR3E02UHBnk7FgGLKb6CjZDIEGB49mLuC1+bH1cm2u8dQ6S+pA=="}]}`),
}

// XXXXXX the root key ID for this trust data is 70eb123c834fd4d2a591fc9a50f4a6d26598fb64a2f37a845296ebbcceae5e24
var trustDataGood = map[string][]byte{
	"timestamp.json": []byte(`{"signed":{"_type":"Timestamp","expires":"2018-09-26T18:14:19.798853706Z","meta":{"snapshot":{"hashes":{"sha256":"BanceUqKl8+J/2MM1YkRz/6XiYiAEGGZU9le+tVE9wg=","sha512":"sFCSdeXAYDKLRwuOBSYUhGL3AZzhoe+mV1/sBFv4VTCnVkVK6kECYButfr9tu/8py02MxPmNuruzAx+UhQTjfA=="},"length":683}},"version":1},"signatures":[{"keyid":"04d342bcbf85148a38539b6ba9fb0b0a422a34a82cc06dcb6b4cd9e63b9d589e","method":"ecdsa","sig":"BD/Vgsc3wYyt3HmffqvpuP++ZyzxAMFZgYeUL6QD1l1uM8fBKQcj6SvR67biZA9JxDKCLpE26QX+tR2JDOijFQ=="}]}`),
	"snapshot.json":  []byte(`{"signed":{"_type":"Snapshot","expires":"2021-09-11T18:14:19.776334163Z","meta":{"root":{"hashes":{"sha256":"vSpjGoZvDxQmvLT68XLnSCGftO4EDUnHH8VZbm5DJAo=","sha512":"vLc+lcVY4vHhLYC5jPXQMkPa3+eB+1nzH2/Ul8mN8zOjiI2I8XiB5BZR1e9IAihniOFD6kOrcm7XZarCMkx6gA=="},"length":2456},"targets":{"hashes":{"sha256":"VSHWgOTfpZP/dxskkbl1j8GzZcJvmEpDSoZj9vhQEZ8=","sha512":"glZ7VLPu4t+MPak1HrG/0Uvh9sP7nHPk+A6ctqv40Ibk/FN6wia5kWQ8ML5Nbl/6+3ACDsDrGLIVCav83M8kpg=="},"length":431}},"version":1},"signatures":[{"keyid":"f3df4027cd8f42f1fe495ff2ff1b818cb63c20b5009c8332cadf20c7755947cc","method":"ecdsa","sig":"TTnj/yD1gmB1V2qo0N32JF4yDJygGp1Q2B80rrwvw4Yvl+cVCsAogw0ur7FwP9Sazpmqm83/lhlJzGG/qN0azg=="}]}`),
	"targets.json":   []byte(`{"signed":{"_type":"Targets","delegations":{"keys":{},"roles":[]},"expires":"2021-09-11T18:14:19.767272538Z","targets":{"latest":{"hashes":{"sha256":"ke9sHFKxZr4CZFuO/uMNHuZTYgJPfaQcQEaBVhc0xGU="},"length":527}},"version":2},"signatures":[{"keyid":"265b2f5e9b10826197023817bf6085a0ad7d6049a896b8c2e142d1aa6120d335","method":"ecdsa","sig":"Oe2Ims6ev/LRCzI7Lly3JCQ0q0ojO852Wkb/k7UNM1+JxY+9CG6IiBus0TUyjcWqp/z17/6IqYGBEC7agLk5Aw=="}]}`),
	"root.json":      []byte(`{"signed":{"_type":"Root","consistent_snapshot":false,"expires":"2028-09-09T18:14:19.751627025Z","keys":{"04d342bcbf85148a38539b6ba9fb0b0a422a34a82cc06dcb6b4cd9e63b9d589e":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwCiPbzcF+AsoqoRfTfE7XYhTH4N3OtmsgpR0wW/yfl0cPQY6G2RLllcPnaSpHRtyNWSfOHZ4iviKqeR5eMMJKA=="}},"265b2f5e9b10826197023817bf6085a0ad7d6049a896b8c2e142d1aa6120d335":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpB/JxTKBuaNI3HBT297sBPYLvMYBb7ftqyNFA9o+BjX9KD0jghRAeu0AL5xs//w7wjXiHBg1OwzivmHZywoQiw=="}},"e7bdb78393989ec18c8de0eb0dbd7799e4335d8e4d6035792e73c1147efe1bf2":{"keytype":"ecdsa-x509","keyval":{"private":null,"public":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJtekNDQVVLZ0F3SUJBZ0lSQUt0OG9EQ3BFV2MwUGpkSGZFTW5MSWd3Q2dZSUtvWkl6ajBFQXdJd05ERXkKTURBR0ExVUVBeE1wWkc5amEyVnlkSEoxYzNSMFpYTjBMbVJ2WTJ0bGNpNXBieTlzYVdKeVlYSjVMMkoxYzNsaQpiM2d3SGhjTk1UZ3dPVEV5TVRneE5ERTFXaGNOTWpnd09UQTVNVGd4TkRFMVdqQTBNVEl3TUFZRFZRUURFeWxrCmIyTnJaWEowY25WemRIUmxjM1F1Wkc5amEyVnlMbWx2TDJ4cFluSmhjbmt2WW5WemVXSnZlREJaTUJNR0J5cUcKU000OUFnRUdDQ3FHU000OUF3RUhBMElBQlBacEljU2o2a0VFb1BwcnZpWFlXUzdpUVZZaC95SjY1MW5ZNjJ2dgpsSmNnS0g5L3Z6aHFJYWp1Rkh6VnNHcml5SksxZ3NuL3RxbFNtZkJENnJKaWhiU2pOVEF6TUE0R0ExVWREd0VCCi93UUVBd0lGb0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QU1CZ05WSFJNQkFmOEVBakFBTUFvR0NDcUcKU000OUJBTUNBMGNBTUVRQ0lDa2xuSWxhQThJN0FiZ3Z5bFJWSWh5TzhCMjVFMitYeVNrOHRVVzh2RHVTQWlBWAp3VTYzaTQ4L094dWl1YWlNUVgrazNtUlpEWkxFM2N0VzQrK3VrZjRSTHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="}},"f3df4027cd8f42f1fe495ff2ff1b818cb63c20b5009c8332cadf20c7755947cc":{"keytype":"ecdsa","keyval":{"private":null,"public":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXzlmJzxNtjK301MDpOuCJjZoVL2lvsJ5rDO8J3Vn/9wJE56MpzbpddSUAe++96/vrLb/V8wXBl3ST2Ihwm1IMQ=="}}},"roles":{"root":{"keyids":["e7bdb78393989ec18c8de0eb0dbd7799e4335d8e4d6035792e73c1147efe1bf2"],"threshold":1},"snapshot":{"keyids":["f3df4027cd8f42f1fe495ff2ff1b818cb63c20b5009c8332cadf20c7755947cc"],"threshold":1},"targets":{"keyids":["265b2f5e9b10826197023817bf6085a0ad7d6049a896b8c2e142d1aa6120d335"],"threshold":1},"timestamp":{"keyids":["04d342bcbf85148a38539b6ba9fb0b0a422a34a82cc06dcb6b4cd9e63b9d589e"],"threshold":1}},"version":1},"signatures":[{"keyid":"e7bdb78393989ec18c8de0eb0dbd7799e4335d8e4d6035792e73c1147efe1bf2","method":"ecdsa","sig":"ly86H7AhAwrQVii6/7Y3aRzjOeIx8o8ROWc9VFgNeZXZinT8r9el2yv0rx6TVFAExumsJF/17FCgoTmIIOEflg=="}]}`),
}

const repositoriesFmt = `{"Repositories":{"busybox":{"busybox:latest":"%s"},"dockertrusttest.docker.io/library/busybox":{"dockertrusttest.docker.io/library/busybox:latest":"%[1]s","dockertrusttest.docker.io/library/busybox@sha256:91ef6c1c52b166be02645b8efee30d1ee65362024f7da41c404681561734c465":"%[1]s"}}}`

// FrozenTrustImagesLinux retags two of the frozen image set for the integration test
// suite so that the fixtured trust data can work on them.  Note that this
// should be changed should the pinned frozen images in the Dockerfile be changed,
// otherwise if it can't find these pinned images exactly, it will download them
// regardless of what images were passed in.
func FrozenTrustImagesLinux(t testing.TB, client client.APIClient, goodTrustMetdadata bool) {
	t.Helper()
	ctx := context.Background()
	info, err := client.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for retag, img := range trustImages {
		if err := pullTagAndRemove(context.Background(), client, img, retag); err != nil {
			t.Fatalf("pullTagAndRemove(%q, %q) error = %v", img, retag, err)
		}
	}
	path := filepath.Join("trustcache", "dockertrusttest.docker.io", "library", "busybox")
	if err := os.MkdirAll(filepath.Join(info.DockerRootDir, path), 0755); err != nil {
		t.Fatal(err)
	}

	td := trustDataBad
	if goodTrustMetdadata {
		td = trustDataGood
	}
	for fname, dataBytes := range td {
		if err := os.WriteFile(filepath.Join(info.DockerRootDir, path, fname), dataBytes, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// repo does not have a digest added until pushed, which we aren't doing here, and the digest is necessary to verify against trust data
	images, err := client.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	imageDigests := make(map[string]string)
	for _, im := range images {
		for _, rt := range im.RepoTags {
			for tag := range trustImages {
				if rt == tag {
					imageDigests[tag] = im.ID
				}
			}
		}
	}
	repositoriesData := []byte(fmt.Sprintf(repositoriesFmt,
		imageDigests["dockertrusttest.docker.io/library/busybox:latest"]))

	err = os.WriteFile(filepath.Join(info.DockerRootDir, "image", info.Driver, "repositories.json"), repositoriesData, 0644)
	if err != nil {
		t.Fatal(err)
	}
}

// WriteConfig writes a custom config file to disk
func WriteConfig(configData string) (string, error) {
	configPath, err := os.MkdirTemp("", "test-daemon-trust")
	if err != nil {
		return "", err
	}
	configFile := filepath.Join(configPath, "config.json")

	err = os.WriteFile(configFile, []byte(configData), 0666)
	if err != nil {
		return "", err
	}
	return configFile, nil
}
