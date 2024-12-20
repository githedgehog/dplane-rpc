#!/bin/bash

cbuild="./clib/build" # N.B. build is gitignored

YELLOW='\e[1;33m'
RED='\e[1;31m'
GREEN='\e[1;32m'
NOCOLOR='\e[0m'
function log () {
	printf "\n${YELLOW} ███████████████ %s ███████████████${NOCOLOR}\n\n" "$1"
}

function log_err () {
	printf "\n${RED} ███████████████ %s ███████████████${NOCOLOR}\n\n" "$1"
}
function log_ok () {
	printf "\n${GREEN} ███████████████ %s ███████████████${NOCOLOR}\n\n" "$1"
}



function c_build () {
	log "Building C library"
	mkdir -p $cbuild && cd $cbuild && cmake -DCMAKE_BUILD_TYPE=Debug -DMAX_ECMP=32 .. 
	if ! cmake --build . ; then
		log_err "Build failed"
		return 1
	fi
	log "Running C tests"
	if ! make test ; then
		log_err "C tests failed"
		return 1
	fi
	return 0
}

function run_echo_server () {
	log "Starting Rust echo server"
	rm /tmp/DP.sock
    cargo run --bin echo &
	return $?
}

function run_mock() {
	# wait for echo server to create socket
	while [[ ! -S /tmp/DP.sock ]]; do
		echo "Waiting for echo server to be ready"
		sleep 1
	done

	log "Starting C cpmock..."
	if ! mock=$(./bin/cpmock 2>&1 > /dev/null) ; then 
		echo "Test failed"
		exit 1
	fi
	log "output of cpmock:" 
	echo "$mock"
	log_ok "Test succeeded"
	return 0
}

function rust_build() {
	log "Building rust crate .."
	cargo build
	return $?
}
function rust_test() {
	log "Running rust tests ..."
	cargo test --lib
	return $?
}



rust_build && rust_test && c_build && run_echo_server && run_mock 

ret=$?
if [ $ret -ne 0 ]; then
	log_err "Something went wrong"
fi

