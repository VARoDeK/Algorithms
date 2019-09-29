.PHONY: all
all: sha256.o sha256

sha256.o: sha256.c
	gcc -c sha256.c -o sha256.o

sha256: Test.c
	gcc sha256.o Test.c -o sha256

.PHONY: clean
clean:
	rm -rf sha256 sha256.o	 
