# SHA256 in C from scratch. (Still in development)

## This code produces right result for only null string for now.

---

From cryptography and encryption point of view, the algorithm works excellent. 

* A unique 256 bit hash is generated for every unique input.

* For a particular input, the same hash is generated everytime.

* Even a small change in input message, changes the hash value drastically.

* It can encrypt the message of upto 2^64 bytes long.

---

The only problem is, for any input (excpet null string or empty message) it is
 not generating the output value which sha256 should generate. Maybe some 
error in implementation. The code is implemented from the pseudocode given on
wikipedia.

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
