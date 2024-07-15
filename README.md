An implementation/study of the SHA2 algorithm in Rust. To run, cd into the SHA2 directory and run the command 'cargo run <message_to_hash>'.

More information about algorithm can be found here: [https://helix.stormhub.org/papers/SHA-256.pdf](https://helix.stormhub.org/papers/SHA-256.pdf)

(ChatGPT's description of the SHA2 hash function)

SHA-2 (Secure Hash Algorithm 2) is a family of cryptographic hash functions designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST). The SHA-2 family consists of six hash functions with digests (hash values) that are 224, 256, 384, 512, 224, and 256 bits long, named as follows: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.

Key Characteristics:
Fixed Size Output: Each function in the SHA-2 family produces a fixed-size output (digest), regardless of the input size. For example, SHA-256 produces a 256-bit (32-byte) hash value.
Input Size: The input to SHA-2 can be of any length.
Collision Resistance: It is computationally infeasible to find two different inputs that produce the same hash output (i.e., hash collision).
Preimage Resistance: Given a hash output, it is computationally infeasible to find the original input.
Avalanche Effect: A small change in the input produces a significantly different output.
Internal Structure:
Message Padding: Before processing, the input message is padded to ensure its length is a multiple of a specific block size (512 bits for SHA-256 and 1024 bits for SHA-512).
Message Schedule: The padded message is divided into blocks, and each block is further divided into words that are expanded into a message schedule.
Compression Function: Each block is processed using a series of logical functions, bitwise operations, and modular additions. This involves initializing a set of working variables and iterating over the message schedule using a sequence of round constants and operations.
Final Hash Value: The output of the compression function for the last block of the message is used to produce the final hash value.
Variants:
SHA-224: Truncated version of SHA-256.
SHA-256: Produces a 256-bit hash value, widely used in various security protocols and applications.
SHA-384: Truncated version of SHA-512.
SHA-512: Produces a 512-bit hash value, suitable for applications requiring high security.
SHA-512/224 and SHA-512/256: Variants of SHA-512, producing shorter hash values (224 and 256 bits, respectively).
Applications:
SHA-2 is widely used in various security applications and protocols, including:

Digital signatures and certificates
TLS/SSL
Cryptographic protocols like PGP, SSH
Blockchain technology
Password hashing
SHA-2 is considered secure and robust, making it a preferred choice for many cryptographic applications.
