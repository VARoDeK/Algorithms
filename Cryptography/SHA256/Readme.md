# SHA256 in C from scratch.

## The code is implemented on the top of pseudo code given on Wikipedia.

---

The algorithm works excellent. 

* A unique 256 bit hash is generated for every unique input.

* For a particular input, the same hash is generated everytime.

* Even a small change in input message, changes the hash value drastically.

* It can encrypt the message of upto (2^64-3) bytes long. (The 3 bytes are used 
for padding).

---

## How to use?

* Just download the repo and run `make` command. An executable file `sha256` 
will be created.
* On command line, run: `./sha256 abc`, where 'abc' is your input message.

---

## How files are working?

* You can re-deign the way, the input is given to hashing algorithm.

* The `sha256.h` contains the function declaration `calculate_sha256` and a 
variable `sha256sum`.

* The function takes input in form of character array. And the final result is 
stored in the variable.

* The `sha256.c` contains all the function definitions. If you don't wanna use 
`make` command, compile the `sha256.c` without linking: 
`gcc -c sha256.c -o sha256.o`. This will create an object file.

* Make another `c` file and include `sha256.h` in it. Then write you code of
taking inut and showing result and all. Then compile it :
`gcc sha256.o your_file.c -o your_file`. 

* This structure was chosen so as if someone wanna build a C library.

* The `Test.c` file has the code to take input from command line for my 
implementation.

---

## References

Wikipedia contributors. SHA-2. Wikipedia, The Free Encyclopedia. September 23, 
2019, 18:08 UTC. Available at: 
https://en.wikipedia.org/w/index.php?title=SHA-2&oldid=917408454. Accessed 
September 30, 2019. 

---
