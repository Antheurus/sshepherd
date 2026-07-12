default:
    @just --list

install:
    bun install

build: install
    bun run build

test: install
    bun run test

check: install
    bun run check

smoke: build
    bash scripts/smoke.sh

clean:
    rm -rf dist node_modules
