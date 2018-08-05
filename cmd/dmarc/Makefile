clean:
	rm -rvf lambda

dependency:
	dep ensure

build: dependency
	GOOS=linux GOARCH=amd64 go build -o dmarc main.go