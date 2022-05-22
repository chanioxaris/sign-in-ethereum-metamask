.PHONY: start

start:
	npm run setup --silent --prefix ui && go run .
