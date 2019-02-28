APP_NAME=packet-generator
DOCKER_REPO=letitbeat
VERSION=`cat version`
.PHONY: test build 
.DEFAULT: help

help: ## Show Help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: ## Launch test and build targets
	test build

dep:  ## Get the required build dependencies
	go get -v -u github.com/golang/dep/cmd/dep

build: ## Build the application
	dep ensure && go build

test:  ## Launch tests
	go test -v ./...

dbuild: ## Build the docker image
	@docker build --force-rm -t $(APP_NAME) .

release: tag login push
push:  ## push the image to docker hub
	@docker push $(DOCKER_REPO)/$(APP_NAME):$(VERSION)
login:
	@echo '$(DOCKER_PASSWORD)' | docker login -u '$(DOCKER_USERNAME)' --password-stdin
tag:  ## Tag the image
	@docker tag $(APP_NAME) $(DOCKER_REPO)/$(APP_NAME):$(VERSION)
vers: ## Output the current version
	@echo $(VERSION)
