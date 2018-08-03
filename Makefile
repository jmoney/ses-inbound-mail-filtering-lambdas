clean:
	rm -rvf lambda

dependency:
	dep ensure

build: dependency
	GOOS=linux GOARCH=amd64 go build -o lambda main.go

package: build
	zip ses-inbound-mail-analyzing-lambda.zip lambda