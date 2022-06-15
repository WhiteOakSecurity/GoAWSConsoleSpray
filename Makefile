TARGET=./build
ARCHS=amd64
LDFLAGS="-s -w"
BINARY_NAME=GoAWSConsoleSpray

darwin:
	@for GOARCH in ${ARCHS}; do \
		echo "Building for darwin $${GOARCH} ..." ; \
		mkdir -p ${TARGET}/${BINARY_NAME}-darwin-$${GOARCH} ; \
		GOOS=darwin GOARCH=$${GOARCH} go build -ldflags=${LDFLAGS} -trimpath -o ${TARGET}/${BINARY_NAME}-darwin-$${GOARCH}/${BINARY_NAME} ; \
	done; \
	echo "Done."
	
windows:
	@for GOARCH in ${ARCHS}; do \
		echo "Building for windows $${GOARCH} ..." ; \
		mkdir -p ${TARGET}/${BINARY_NAME}-windows-$${GOARCH} ; \
		GOOS=windows GOARCH=$${GOARCH} go build -ldflags=${LDFLAGS} -trimpath -o ${TARGET}/${BINARY_NAME}-windows-$${GOARCH}/${BINARY_NAME}.exe ; \
	done; \
	echo "Done."
	
linux:
	@for GOARCH in ${ARCHS}; do \
		echo "Building for linux $${GOARCH} ..." ; \
		mkdir -p ${TARGET}/${BINARY_NAME}-linux-$${GOARCH} ; \
		GOOS=linux GOARCH=$${GOARCH} go build -ldflags=${LDFLAGS} -trimpath -o ${TARGET}/${BINARY_NAME}-linux-$${GOARCH}/${BINARY_NAME} ; \
	done; \
	echo "Done."

all: clean linux windows darwin

clean:
	@rm -rf ${TARGET} ; \
	go clean ./... ; \
	echo "Done."

dep:
	go mod download ; \
	echo "Done."