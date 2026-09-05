.PHONY: test build smoke gui-smoke webdav-smoke clean cross

test:
	go test ./...

build:
	go build -o bin/seavault ./cmd/seavault

smoke: build
	./scripts/smoke-test.sh ./bin/seavault
	./scripts/gui-api-smoke-test.sh ./bin/seavault
	./scripts/rsync-put-smoke-test.sh ./bin/seavault
	./scripts/webdav-file-manager-smoke-test.sh ./bin/seavault

gui-smoke: build
	./scripts/gui-api-smoke-test.sh ./bin/seavault
	./scripts/rsync-put-smoke-test.sh ./bin/seavault
	./scripts/webdav-file-manager-smoke-test.sh ./bin/seavault

webdav-smoke: build
	./scripts/webdav-file-manager-smoke-test.sh ./bin/seavault
	./scripts/webdav-file-manager-smoke-test.sh ./bin/seavault

cross:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -o dist/seavault-linux-amd64 ./cmd/seavault
	GOOS=darwin GOARCH=arm64 go build -o dist/seavault-darwin-arm64 ./cmd/seavault
	GOOS=windows GOARCH=amd64 go build -o dist/seavault-windows-amd64.exe ./cmd/seavault

clean:
	rm -rf bin dist
