#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="/tmp/ossec-build"

set -e

function prepare() {
	if [ -d "${BUILD_DIR}" ]; then
		rm -rf 	"${BUILD_DIR}"
	fi

	mkdir "${BUILD_DIR}"

	sudo yum install -y libuv-devel.x86_64 zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel expat-devel python-pip libcurl-devel libsodium-devel libuv-static libasan
}

function install_protoc() {
	pushd "${BUILD_DIR}"
		curl -OL https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip
		unzip protoc-3.2.0-linux-x86_64.zip -d protoc3
		sudo mv protoc3/bin/* /usr/local/bin/
		sudo mv protoc3/include/* /usr/local/include/
		sudo chown $USER /usr/local/bin/protoc
		sudo chown -R $USER  /usr/local/include/google
	popd
}

function install_python_protobuf() {
	sudo pip install --upgrade pip
	sudo pip install --upgrade protobuf
}


function install_nanopb() {
	pushd "${BUILD_DIR}"
		git clone https://github.com/nanopb/nanopb.git
		cd nanopb
		mkdir _build && cd _build
		cmake ..
		make -j8
		sudo make install
	popd
}

prepare
install_protoc
install_python_protobuf
install_nanopb


