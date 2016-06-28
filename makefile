
build:
	mvn -q -B package appassembler:assemble

run:
	bash target/appassembler/bin/app
