# SHA256 in C from scratch.

## This code produces right result for only null string for now.

---

The algorithm works excellent. 

* A unique 256 bit hash is generated for every unique input.

* For a particular input, the same hash is generated everytime.

* Even a small change in input message, changes the hash value drastically.

* It can encrypt the message of upto (2^64-3) bytes long. (The 3 bytes are used 
for padding).

---

## How to use?

* Just download the repo and run `make` command. A executable file `sha256` 
will be created.
* On command line, run: `./sha256 abc`, where 'abc' is your inout message.

* You can re-deign the way, the input is given to hashing algorithm.

* The `sha256.h` contains the function declaration `calculate_sha256` and a 
variable `sha256sum`.

* The function takes input in form of character array. And the final result is 
stored in the variable.

---
