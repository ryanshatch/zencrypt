# Flowchart Explanation

### Algorithms and Data Structures Flowchart Explanation:

1. **User Chooses Method**\
   The user decides whether they want to encrypt a large file, use elliptic-curve cryptography, or generate Argon2 hashes (instead of SHA-256).
2. **Check for Advanced Algorithms**
   * If advanced algorithms (ECC, Argon2) are selected, Zencrypt initializes those cryptographic methods and any parameters, for example ECC curves or Argon2 memory cost.
   * Otherwise, it defaults to existing methods like AES or SHA-256.
3. **Check Concurrency Option**
   * If enabled (for example, for large files), Zencrypt uses a multithreading or multiprocessing approach to handle chunk-based encryption or hashing in parallel.
4. **Chunk File (If Using Concurrency)**
   * For large file encryption, read the file in small chunks, place them in a queue or list, and then distribute them to worker threads/processes.
   * If concurrency is **off**, a simpler single-pass encryption or hashing routine is used.
5. **Parallel Processing**
   * Each worker encrypts or hashes its chunk with the chosen algorithm.
   * This step significantly speeds up the process on multi-core systems.
6. **Reassemble Results**
   * Combine or stream the partially encrypted chunks into the final file or combine hashed outputs.
   * In a hashing scenario, you might incorporate a final combine step (for example, using a Merkle tree approach).
     1. **Output**
        * Write the final encrypted file or final hash to its destination.
        * Provide a success message or handle errors as needed.
