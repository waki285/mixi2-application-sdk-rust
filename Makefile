SHELL=/bin/bash -o pipefail

.PHONY: test
test:
	go test -v ./...
