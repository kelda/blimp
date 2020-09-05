module github.com/kelda-inc/blimp

go 1.13

// Required to build github.com/moby/buildkit:
// * https://github.com/golang/go/issues/35787
// * https://github.com/containerd/containerd/issues/3031#issuecomment-541737892
replace (
	github.com/containerd/containerd v1.3.0-0.20190507210959-7c1e88399ec0 => github.com/containerd/containerd v1.3.0-beta.2.0.20190823190603-4a2f61c4f2b4
	github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309
	golang.org/x/crypto v0.0.0-20190129210102-0709b304e793 => golang.org/x/crypto v0.0.0-20180904163835-0709b304e793
)

require (
	github.com/GeertJohan/go.rice v1.0.0
	github.com/Masterminds/semver v1.5.0
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/buger/goterm v0.0.0-20200322175922-2f3e71b85129
	github.com/cesanta/docker_auth/auth_server v0.0.0-20200309093330-99bfe0217f59
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/daaku/go.zipexe v1.0.1 // indirect
	github.com/docker/cli v0.0.0-20200320120634-22acbbcc4b3f
	github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c

	// At the moment, the latest release doesn't contain the yaml.UnmarshalStrict
	// and yaml.DisallowUnknownFields functions. This override vendors the latest
	// commit on `master`.
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/golang/protobuf v1.4.2
	github.com/google/go-containerregistry v0.1.0
	github.com/googleapis/gnostic v0.4.0 // indirect
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/gorilla/websocket v1.4.2
	github.com/kelda/blimp v0.0.0-20200909003631-c5b0c42f7137
	github.com/kelda/compose-go v0.0.0-20200902144940-ad3de8621596
	github.com/lithammer/dedent v1.1.0
	github.com/miekg/dns v1.1.28
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/afero v1.2.2
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.5.1
	github.com/syncthing/syncthing v1.6.1
	github.com/willf/bitset v1.1.10 // indirect
	github.com/willf/bloom v2.0.3+incompatible // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	google.golang.org/grpc v1.29.1
	gopkg.in/ldap.v2 v2.5.1 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.17.4
	k8s.io/cli-runtime v0.17.3
	k8s.io/client-go v0.17.4
	k8s.io/kubectl v0.17.3
)
