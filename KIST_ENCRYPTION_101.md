# Kist Encryption 101

A clear, practical guide to how Kist protects secrets, why every piece exists, and how the underlying cryptography ensures maximum safety with minimum operational friction.

---

## 1. The Core Mission: Practical Security

Storing plaintext secrets in code repositories or databases creates immense operational risk. A single leaked database dump, backup snapshot, or misconfigured Git repository can compromise an entire system.

**Kist** solves this by enforcing authenticated encryption at rest and in version control. It transforms human-readable configurations into tamper-proof, encrypted binary packages (called **envelopes**) before they ever touch disk, Git, or PostgreSQL.

```
                      +-------------------+
                      |   Your Secret     |
                      | ("api_key_12345") |
                      +---------+---------+
                                |
                                v
               +---------------------------------+
               |       Kist Encryption Engine    |
               | (Argon2id KDF + AES-256-GCM)    |
               +----------------+----------------+
                                |
                                v
                      +-------------------+
                      | Encrypted Envelope|
                      |   (Safe Binary)   |
                      +---------+---------+
                                |
                +---------------+---------------+
                |                               |
                v                               v
       +-----------------+             +-----------------+
       | PostgreSQL DB   |             | Git Repository  |
       |  (table: kist)  |             | (.kist / YAML)  |
       +-----------------+             +-----------------+
```

---

## 2. The Key Ingredients: What Does What?

To understand Kist's security, think of it as a high-security safe requiring several distinct components to lock and unlock.

| Component | Technical Name | Real-World Analogy | Why It Exists |
| :--- | :--- | :--- | :--- |
| **Profile Password** | Master Secret | The secret combination in your head | The root credential used to generate encryption keys. |
| **Salt** (16 bytes) | Cryptographic Salt | A unique grain pattern for each lock | Ensures two profiles with identical passwords produce completely different encryption keys. Defeats precomputed attacks (rainbow tables). |
| **Key Derivation** | Argon2id | The heavy mechanical gear that takes effort to turn | Intentionally consumes CPU time and memory (64 MB RAM) so attackers cannot brute-force passwords using high-speed GPUs. |
| **Derived Key** (32 bytes) | AES-256 Key | The custom physical key cut by the machine | The actual 256-bit key used to encrypt the payload. Never stored on disk. |
| **Nonce / IV** (12 bytes) | Initialization Vector | A single-use random lock serial number | Guarantees that encrypting the exact same secret twice results in completely different ciphertext. |
| **Encryption Engine** | AES-256-GCM | An armored box with a tamper-evident seal | Encrypts the data (confidentiality) and computes an authentication tag (integrity). |
| **Context / AAD** | Authenticated Additional Data | The shipping label glued to the box | Binds the ciphertext to its specific environment, project, profile, key name, and version so attackers cannot swap or transplant secrets. |
| **Envelope** | `password-v1` Envelope | The final sealed shipping parcel | The standardized binary package containing the header metadata, salt, nonce, context hash, and ciphertext. |

---

## 3. How Encryption Works (Step-by-Step)

When you run `kist lock` or store a value via the Python API, Kist performs the following operations:

```
[Profile Password] + [Fresh 16-byte Salt]
               │
               ▼ (Argon2id: 64MB RAM, 2 iterations, 4 lanes)
       [32-byte AES-256 Key]
               │
               ▼
[Plaintext Secret] + [Fresh 12-byte Nonce] + [Context (Org/Project/Key/Version)]
               │
               ▼ (AES-256-GCM)
   [Ciphertext + 16-byte Auth Tag]
               │
               ▼
   [Pack into Binary Envelope]
```

### Step 1: Stretch the Password with Argon2id
Computers can guess millions of simple passwords per second using GPUs. To prevent this, Kist passes your profile password and a freshly generated 16-byte random salt through **Argon2id**.
- **Memory Cost:** 65,536 KiB (64 MB)
- **Iterations:** 2 passes
- **Parallel Lanes:** 4 threads
- **Result:** A strong, high-entropy 256-bit AES key derived specifically for this single operation.

### Step 2: Bind the Context (Authenticated Additional Data)
To prevent "ciphertext transplant" attacks (where an attacker copies an encrypted database value from a test environment to a production record), Kist creates a deterministic JSON metadata structure:

* **For Database Records (`kist-db-v1`):**
  ```json
  {
    "format": "kist-db-v1",
    "organization_id": "...",
    "project_id": "...",
    "profile_id": "...",
    "profile": "production",
    "secret_key": "database.password",
    "secret_version": "3"
  }
  ```

* **For Git Secret Files (`kist-git-v1`):**
  ```json
  {
    "format": "kist-git-v1",
    "organization": "local",
    "project": "default",
    "profile": "production",
    "repository": "my-repo",
    "path": "secrets/production.yaml"
  }
  ```

### Step 3: Encrypt with AES-256-GCM
Kist encrypts the serialized JSON plaintext using AES-256 in Galois/Counter Mode (GCM) using:
- The derived 256-bit key
- A fresh, random 12-byte nonce
- The context metadata as Associated Data (AAD)

AES-256-GCM produces both the **ciphertext** and a **16-byte authentication tag**. If even a single bit of the ciphertext or context is modified, decryption immediately fails.

### Step 4: Assemble the Binary Envelope
Kist packages the metadata, parameters, salt, nonce, and ciphertext into a compact binary format.

---

## 4. Inside the Kist Binary Envelope

Every encrypted secret stored by Kist starts with a self-describing binary header:

```
+---------------+---------------+---------------+---------------+
| Magic (4B)    | Version (1B)  | Algo (1B)     | KDF (1B)      |
| "KIST"        | 0x01          | 0x01 (AES-GCM)| 0x01 (Argon2) |
+---------------+---------------+---------------+---------------+
| Flags (1B)    | Memory Cost (4B, uint32)                      |
| 0x00          | e.g. 65536 KiB                                |
+---------------+---------------+---------------+---------------+
| Iterations (4B, uint32)       | Lanes (2B, uint16)            |
| e.g. 2                        | e.g. 4                        |
+---------------+---------------+---------------+---------------+
| Salt (16 Bytes, Random)                                       |
+---------------------------------------------------------------+
| Nonce (12 Bytes, Random)                                      |
+---------------------------------------------------------------+
| SHA-256 Hash of Context (32 Bytes)                            |
+---------------------------------------------------------------+
| Ciphertext + AES-GCM Auth Tag (Variable Length)               |
+---------------------------------------------------------------+
```

### Why this design matters:
1. **Self-Describing:** Future versions can update cryptographic algorithms without breaking legacy decryption.
2. **Deterministic Context Verification:** The 32-byte SHA-256 hash allows Kist to verify context alignment before attempting cryptographic operations.
3. **Collision-Proof:** Every single write generates fresh random bytes for both salt and nonce.

---

## 5. How Decryption Works

When an authorized service requests a secret (`kist.get("database.password")` or `kist unlock`):

```
                       [Encrypted Envelope]
                                │
                                ▼
               [Validate Header ("KIST", v1, etc.)]
                                │
                                ▼
               [Verify Context Hash vs Current Scope]
                    (Fails if transplanted)
                                │
                                ▼
             [Re-derive Key using Argon2id + Stored Salt]
                                │
                                ▼
         [AES-256-GCM Decrypt (Ciphertext + Nonce + Context)]
                                │
               ┌────────────────┴────────────────┐
               ▼                                 ▼
      [Authentication Succeeded]        [Tampered or Wrong Key]
               │                                 │
               ▼                                 ▼
        [Return Plaintext]             [Raise DecryptionError]
```

1. **Envelope Validation:** Kist checks the `KIST` magic header, envelope version, and Argon2 parameters.
2. **Context Check:** Kist reconstructs the expected context for the requested key and profile, comparing its SHA-256 hash against the envelope's header.
3. **Key Re-derivation:** Argon2id derives the exact AES-256 key using the envelope's salt and the user's password.
4. **AEAD Decryption:** AES-256-GCM decrypts and verifies the ciphertext. If the password is wrong or any bytes were altered, it raises a `DecryptionError`.

---

## 6. Password Management & Storage Security

Kist avoids storing keys in plaintext locations:

* **File System (`~/.kist/pwd_<profile>`):**
  - Enforces strict POSIX file permissions (`0600` - read/write only by owner).
  - Enforces directory permissions (`0700` - accessible only by owner).
  - Prohibits symlinks to prevent symlink redirect attacks.
  - Generates 32-byte high-entropy URL-safe passwords by default.
* **Environment Variables:**
  - `KIST_PASSWORD` or `KIST_PASSWORD_<PROFILE>` (ideal for CI/CD and container runtimes).

---

## 7. Database & Concurrency Protections

In addition to cryptography, Kist protects data integrity inside PostgreSQL:

* **Row-Level Versioning:** Every secret has an incrementing `secret_version` column.
* **Row-Level Locking:** Updates use `SELECT ... FOR UPDATE` with retry loops to eliminate race conditions between concurrent writers.
* **Transaction Advisory Locks:** Batch locking operations (`lock_yaml`) acquire PostgreSQL session advisory locks (`pg_advisory_xact_lock`) scoped to the profile.
* **Transport Encryption:** TLS (`sslmode=require`, `verify-ca`, or `verify-full`) is enforced in production environments (`KIST_ENV=production`).

---

## 8. Quantum Safety & Long-Term Security (Post-Quantum Resistance)

A common concern when storing sensitive data is whether encrypted secrets will remain secure against future advances in quantum computing ("harvest now, decrypt later" attacks).

**Kist’s core encryption architecture (Argon2id + AES-256-GCM) is quantum-resistant.**

```
┌──────────────────────────────────────┬──────────────────────────────────────┐
│ Asymmetric / Public-Key (Broken)     │ Symmetric & KDFs (Quantum-Resistant) │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ • RSA, ECC, ECDSA, Diffie-Hellman   │ • Argon2id, AES-256-GCM, BLAKE2b     │
│ • Broken by Shor's Algorithm        │ • Subject only to Grover's Algorithm │
│   (Polynomial-time algebraic break)  │   (Quadratic reduction: 256 -> 128)  │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

### Why Kist Envelopes Are Quantum-Safe:

1. **Immunity to Shor’s Algorithm:**
   Shor's algorithm compromises asymmetric cryptosystems (like RSA and elliptic curve cryptography) by solving discrete logarithms and prime factorizations in polynomial time. Argon2id and AES-256 are purely symmetric, permutation-based constructions that do not rely on algebraic number theory. Shor's algorithm has zero applicability to Kist envelopes.

2. **Grover's Algorithm Resistance (128-Bit Security Margin):**
   Grover’s algorithm provides a quadratic speedup for unstructured brute-force search against symmetric ciphers, effectively halving the key space ($n \rightarrow n/2$). Because Kist uses **AES-256** (a 256-bit key), an attacker utilizing Grover’s algorithm still faces an effective complexity of **$2^{128}$ operations**. Breaking a $2^{128}$ search space remains computationally and physically infeasible under known physical and thermodynamic constraints.

3. **Memory-Hard Quantum Penalty:**
   Argon2id is explicitly memory-hard (requiring 64 MB RAM per evaluation). Implementing memory-intensive graph traversal on quantum hardware requires maintaining massive arrays of fault-tolerant, error-corrected qubits with enormous $T$-gate circuit depth. This imposes extreme financial and physical overhead per guess for any hypothetical quantum adversary.

4. **Algorithm Agility for Future Risk Mitigation:**
   Kist’s self-describing binary header explicitly records the KDF and cipher version. If future cryptographic breakthroughs necessitate parameter migration or post-quantum algorithm transitions, the architecture accommodates seamless upgrades without invalidating legacy envelopes.

---

## 9. Summary of Rules for Users

1. **Protect Profile Passwords:** Never commit `~/.kist/pwd_*` files or plaintext passwords to version control.
2. **Rely on Context Integrity:** A secret encrypted for `profile="staging"` cannot be decrypted under `profile="production"` even if both share the same password.
3. **Check File Permissions:** Ensure the `.kist` directory is owned by your user and inaccessible to other system accounts.
4. **Enable TLS in Production:** Ensure PostgreSQL connections use TLS verification (`verify-full` or `verify-ca`) to prevent man-in-the-middle attacks.

---

## 10. Acknowledgments & Cryptographic Primitives

Cryptographic primitives (AES-256-GCM AEAD and Argon2id KDF) are powered by the standard Python Cryptographic Authority ([`cryptography`](https://github.com/pyca/cryptography)) library.
