ROOT := $(PWD)
CMDDIR := cmd
CMDPATHS := $(shell find $(CMDDIR) -type d -mindepth 1 -maxdepth 1)
BINARIES := $(foreach path, $(CMDPATHS), $(shell basename $(path)))

%:
	@cd $(CMDDIR)/$@ && go build -v	-o $(ROOT)/bin/$@

test:
	@go test -v ./...

clean:
	@rm -rvf bin/