clean:
	rm -rvf lambda

dependency:
	dep ensure

build: dependency
	GOOS=linux GOARCH=amd64 go build -o block main.go