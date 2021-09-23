.PHONY: build
build:
	cargo build

.PHONY: run
run:
	cargo run

.PHONY: init
init:
	mkdir -p rootfs
	docker export $(shell docker create busybox) | tar -C rootfs -xvf -
