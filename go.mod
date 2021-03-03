module intel/isecl/go-trust-agent/v3

require (
	github.com/apache/thrift v0.12.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/intel-secl/intel-secl/v3 v3.3.1
	github.com/jinzhu/gorm v1.9.15
	github.com/openzipkin/zipkin-go v0.1.6 // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/vmware/govmomi v0.22.2
	golang.org/x/crypto v0.0.0-20191205180655-e7c4368fe9dd
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/yaml.v2 v2.3.0
	intel/isecl/lib/clients/v3 v3.3.1
	intel/isecl/lib/common/v3 v3.3.1
	intel/isecl/lib/platform-info/v3 v3.3.1
	intel/isecl/lib/tpmprovider/v3 v3.3.1
)

replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.3.1

replace intel/isecl/lib/tpmprovider/v3 => github.com/intel-secl/tpm-provider/v3 v3.3.1

replace intel/isecl/lib/platform-info/v3 => github.com/intel-secl/platform-info/v3 v3.3.1

replace intel/isecl/lib/clients/v3 => github.com/intel-secl/clients/v3 v3.3.1

replace github.com/vmware/govmomi => github.com/arijit8972/govmomi fix-tpm-attestation-output

replace github.com/intel-secl/intel-secl/v3 => github.com/kwtj43/intel-secl/v3 task/isecl-14326-host-info-updates