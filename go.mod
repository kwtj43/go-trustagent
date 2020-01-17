module intel/isecl/go-trust-agent

require (
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.11
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/clients v1.0.0
	intel/isecl/lib/common v1.0.0-Beta
	intel/isecl/lib/platform-info v1.0.0
	intel/isecl/lib/tpmprovider v1.0.0
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v2.0/develop

replace intel/isecl/lib/tpmprovider => gitlab.devtools.intel.com/sst/isecl/lib/tpm-provider.git v2.0/go-trust-agent

replace intel/isecl/lib/platform-info => gitlab.devtools.intel.com/sst/isecl/lib/platform-info.git v2.0/go-trust-agent

replace intel/isecl/lib/clients => gitlab.devtools.intel.com/sst/isecl/lib/clients.git v2.0/develop
