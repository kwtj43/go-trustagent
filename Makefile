GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
GITBRANCH := $(CI_COMMIT_BRANCH)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)
VERSION := $(or ${GITTAG}, v1.0.0)

# TODO:  Update make file to support debug/release builds (release build to use secure gcflags)
# -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D
gta:
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/v3/util.Branch=$(GITBRANCH) -X intel/isecl/go-trust-agent/v3/util.Version=$(VERSION) -X intel/isecl/go-trust-agent/v3/util.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/v3/util.BuildDate=$(BUILDDATE)" -o out/tagent

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.21.0/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.16/swagger-codegen-cli-3.0.16.jar -O /usr/local/bin/swagger-codegen-cli.jar

swagger-doc: 
	mkdir -p out/swagger
	export CGO_CFLAGS_ALLOW="-f.*"; /usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

docker_image: 
	mkdir -p out/docker-image
	cp dist/docker/Dockerfile out/docker-image
	cp out/tagent out/docker-image
	chmod +x out/docker-image/tagent
	cd out/docker-image && docker build --tag=trust-agent-container --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${http_proxy} .

installer: gta
	mkdir -p out/installer
	cp dist/linux/tagent.service out/installer/tagent.service
	cp dist/linux/tagent_init.service out/installer/tagent_init.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/module_analysis.sh out/installer/module_analysis.sh && chmod +x out/installer/module_analysis.sh
	cp dist/linux/module_analysis_da.sh out/installer/module_analysis_da.sh && chmod +x out/installer/module_analysis_da.sh
	cp dist/linux/module_analysis_da_tcg.sh out/installer/module_analysis_da_tcg.sh && chmod +x out/installer/module_analysis_da_tcg.sh
	cp dist/linux/manifest_tpm20.xml out/installer/manifest_tpm20.xml
	cp dist/linux/manifest_wlagent.xml out/installer/manifest_wlagent.xml

	cd tboot-xm && $(MAKE) package
	cp tboot-xm/out/application-agent*.bin out/installer/
	
	cp out/tagent out/installer/tagent
	makeself out/installer out/trustagent-$(VERSION).bin "TrustAgent $(VERSION)" ./install.sh

unit_test_bin:
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct go build -tags=unit_test -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/v3/util.Branch=$(GITBRANCH) -X intel/isecl/go-trust-agent/v3/util.Version=$(VERSION) -X intel/isecl/go-trust-agent/v3/util.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/v3/util.BuildDate=$(BUILDDATE)" -o out/tagent

unit_test: unit_test_bin
	mkdir -p out
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct go test ./... -tags=unit_test -coverpkg=./... -coverprofile out/cover.out
	go tool cover -func out/cover.out
	go tool cover -html=out/cover.out -o out/cover.html

all: clean installer

clean:
	cd tboot-xm && $(MAKE) clean
	rm -rf out/
