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
       |  (Zero-Knowledge|             | (.kist / YAML)  |
       |   kist_secrets) |             |                 |
       +-----------------+             +-----------------+
```

---

## 2. The Key Ingredients: What Does What?

To understand Kist's security, think of it as a multi-tier vault requiring several distinct components to lock, index, and unlock secrets.

| Component | Technical Name | Real-World Analogy | Why It Exists |
| :--- | :--- | :--- | :--- |
| **Profile Password** | Master Secret | The master combination in your head | The root credential used to generate Key Encryption Keys (KEK). |
| **Salt** (16 bytes) | Cryptographic Salt | A unique grain pattern for each lock | Ensures two profiles with identical passwords produce completely different encryption keys. Defeats precomputed rainbow tables. |
| **Key Derivation** | Argon2id | The heavy mechanical gear that takes effort to turn | Intentionally consumes CPU time and memory (64 MB RAM) so attackers cannot brute-force passwords using high-speed GPUs or ASICs. |
| **Key Encryption Key (KEK)** | 256-bit AES Key | The master vault key | Derived via Argon2id from the password; wraps and protects the random profile Key Bundle. |
| **Key Bundle** | `_KeyBundle` (Content + Index Keys) | The inner safety-deposit key ring | Contains two randomly generated 256-bit keys: a **Data Encryption Key (DEK / `content_key`)** and a **Blind Index Key (`index_key`)**. |
| **Data Encryption Key (DEK)** | 256-bit AES Key | The swift everyday safety deposit key | Directly encrypts individual secret payloads in PostgreSQL with AES-256-GCM in microseconds without repeating expensive Argon2id derivations on every read. |
| **Index Key** | 256-bit HMAC Key | The blind catalogue encoder | Derives 32-byte deterministic HMAC-SHA256 lookup tokens so database queries find secrets without leaking plaintext secret names. |
| **Nonce / IV** (12 bytes) | Initialization Vector | A single-use random lock serial number | Guarantees that encrypting the exact same secret twice results in completely different ciphertext. |
| **Encryption Engine** | AES-256-GCM | An armored box with a tamper-evident seal | Encrypts the payload (confidentiality) and computes a 16-byte authentication tag (integrity). |
| **Context / AAD** | Authenticated Additional Data | The indelible shipping label glued to the box | Binds ciphertexts to their exact organization, project, profile, key, and version so attackers cannot swap or transplant records. |
| **Envelope** | `password-v1` Envelope | The final sealed shipping parcel | The standardized binary package containing header metadata, salt, nonce, context hash, and ciphertext. |

---

## 3. Two-Tier Envelope Architecture (KEK / DEK)

Kist uses two complementary encryption models tailored for operational performance and zero-knowledge storage:

### A. Git Secret Files (`kist-git-v1`)
For Git-managed files (`secrets/<profile>.yaml`), Kist uses direct file-level envelope encryption:
```
[Profile Password] + [Fresh 16-byte Salt]
               │
               ▼ (Argon2id: 64MB RAM, 2 iterations, 4 lanes)
       [32-byte AES-256 KEK]
               │
               ▼
[YAML Payload] + [Fresh 12-byte Nonce] + [Git Context (Org/Project/Profile/Path)]
               │
               ▼ (AES-256-GCM)
   [Ciphertext + 16-byte Auth Tag]
               │
               ▼
   [Pack into Binary Envelope]
```

### B. PostgreSQL Database Storage (`kist-db-v1`)
In PostgreSQL, individual secret reads (`store.get(...)`) occur frequently at application runtime. Running a 64 MB Argon2id key derivation on every single key read would introduce unacceptable latency and CPU bottlenecks.

Instead, Kist employs a **Two-Tier Envelope Model**:

```
1. UNWRAPPING THE KEY BUNDLE (Once per Profile Session):
[Profile Password] + [Stored Bundle Salt]
               │
               ▼ (Argon2id KEK Derivation)
       [32-byte AES-256 KEK]
               │
               ▼ (AES-256-GCM Decrypt wrapped_bundle)
   [Key Bundle: Content Key (DEK) + Index Key]

2. RETRIEVING & DECRYPTING A SECRET (Microsecond Operations):
   [Secret Name] + [Index Key] ──> HMAC-SHA256 ──> [32-byte Lookup Token]
                                                           │
                                                           ▼ (Query DB)
                                                [kist_secrets Record]
                                                           │
                                                           ▼ (AES-256-GCM Decrypt with DEK)
                                                 [Decrypted Secret Value]
```

1. **Key Bundle Wrapping:** A random 256-bit `content_key` and 256-bit `index_key` are generated and wrapped using the Argon2id-derived KEK in `kist_key_bundles`.
2. **Secret Payload Encryption:** Secret values in `kist_secrets` are encrypted using the fast `content_key` (DEK) with AES-256-GCM and bound to scope and version metadata.
3. **Zero-Knowledge Indexing:** Plaintext secret names are hashed into 32-byte HMAC-SHA256 tokens using the `index_key`.

---

## 4. Context & Authenticated Additional Data (AAD)

To prevent "ciphertext transplant" attacks (where an attacker copies an encrypted record from a development environment into production), Kist creates deterministic JSON metadata structures bound to every cryptographic operation:

### 1. Database Secret Context (`kist-db-v1`)
Binds the encrypted secret value to its organization, project, profile, key bundle, and version:
```json
{
  "format": "kist-db-v1",
  "organization_id": "018f23a1-...",
  "project_id": "018f23a1-...",
  "profile_id": "018f23a1-...",
  "profile": "production",
  "key_bundle_id": "018f23a2-...",
  "secret_version": "3"
}
```

### 2. Blind Lookup Token Context (`kist-name-index-v1`)
Binds the HMAC-SHA256 secret name hash to its scope context:
```json
{
  "format": "kist-name-index-v1",
  "organization_id": "018f23a1-...",
  "project_id": "018f23a1-...",
  "profile_id": "018f23a1-...",
  "profile": "production",
  "secret_key": "third_party.stripe.api_key"
}
```

### 3. Key Bundle Context (`kist-bundle-v1`)
Binds the wrapped key bundle to its profile and bundle ID:
```json
{
  "format": "kist-bundle-v1",
  "organization_id": "018f23a1-...",
  "project_id": "018f23a1-...",
  "profile_id": "018f23a1-...",
  "profile": "production",
  "bundle_id": "018f23a2-..."
}
```

### 4. Git Secret File Context (`kist-git-v1`)
Binds Git secret files to the repository and relative file path:
```json
{
  "format": "kist-git-v1",
  "organization": "local",
  "project": "default",
  "profile": "production",
  "repository": "my-service-repo",
  "path": "secrets/production.yaml"
}
```

---

## 5. Inside the Kist Binary Envelopes

Every encrypted payload stored by Kist starts with a self-describing binary header:

### A. Password-Derived Envelope Format (`password-v1`)
Used for Git files and wrapped key bundles:

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

### B. Direct Raw DEK Payload Format (Database Secrets)
Used for high-throughput database secret blobs in `kist_secrets`:

```
+---------------+---------------+---------------+---------------+
| Magic (4B)    | Version (1B)  | Algo (1B)     | Flags (2B)    |
| "KIST"        | 0x01          | 0x02 (RAW-GCM)| 0x0000        |
+---------------+---------------+---------------+---------------+
| Nonce (12 Bytes, Random)                                      |
+---------------------------------------------------------------+
| SHA-256 Hash of Context (32 Bytes)                            |
+---------------------------------------------------------------+
| Ciphertext + AES-GCM Auth Tag (Variable Length)               |
+---------------------------------------------------------------+
```

---

## 6. How Decryption Works

When an authorized application retrieves a secret (`store.get("stripe.api_key")` or `kist unlock`):

```
1. UNWRAP KEY BUNDLE (Session Initialization)
   Fetch wrapped_bundle from `kist_key_bundles`
   Derive KEK via Argon2id(master_password, bundle_salt)
   AES-256-GCM Decrypt wrapped_bundle -> (content_key, index_key)

2. COMPUTE ZERO-KNOWLEDGE LOOKUP TOKEN
   lookup_token = HMAC-SHA256(index_key, name_context)

3. FETCH & DECRYPT SECRET RECORD
   SELECT encrypted_blob FROM kist_secrets
   WHERE profile_id = %s AND lookup_token = %s

4. CONSTANT-TIME INTEGRITY & DECRYPTION CHECK
   Verify Context Hash in header matches expected AAD
   AES-256-GCM Decrypt encrypted_blob using content_key
   Verify token matches hmac.compare_digest(lookup_token, token)
   Return secret plaintext value
```

If the master password is wrong, the scope does not match, or any ciphertext byte has been altered, Kist fails closed immediately and raises `DecryptionError`.

---

## 7. Zero-Knowledge Database Hierarchy & Schema

Kist structures PostgreSQL storage into an isolated relational hierarchy:

```
kist_organizations
    └── kist_projects
            └── kist_profiles
                    ├── kist_key_bundles (wrapped content & index keys)
                    └── kist_secrets     (HMAC lookup tokens & encrypted payloads)
```

### Schema Guarantees:
1. **Zero Plaintext Secret Names:** Plaintext names (like `stripe.secret_key` or `postgres.password`) are never stored in database columns, query parameters, index structures, or query logs. Lookups query 32-byte HMAC digests.
2. **Version Monotonicity:** Every mutation increments `secret_version`, preventing replay and rollback attacks.
3. **Transaction Advisory Locking:** Writes acquire PostgreSQL advisory locks (`pg_advisory_xact_lock`) scoped to the profile to eliminate concurrency races.
4. **Row-Level Write Isolation:** Programmatic single-key updates (`kist.set`) use `SELECT ... FOR UPDATE` with automatic retry loops.
5. **Real-Time Cache Synchronization:** Database writes trigger PostgreSQL `NOTIFY kist_secret_updated`, allowing runtime stores (`DynamicSecretStore`) to invalidate in-memory caches instantly.

---

## 8. Password Management & Storage Security

Kist avoids storing passwords or plaintext keys in unsecured locations:

* **Local Key Files (`~/.kist/pwd_<profile>`):**
  - Enforces strict POSIX permissions (`0600` on key files, `0700` on directory).
  - Prohibits symlinks to prevent symlink traversal attacks.
  - Generates 32-byte high-entropy URL-safe passwords via `kist profile create <name>`.
* **Environment Variables:**
  - `KIST_PASSWORD_<NAME>` (profile-specific, recommended for CI/CD).
  - `KIST_PASSWORD` (global fallback).

---

## 9. Quantum Safety & Long-Term Security (Post-Quantum Resistance)

A common concern when storing sensitive data is whether encrypted secrets will remain secure against future advances in quantum computing ("harvest now, decrypt later" attacks).

**Kist’s core encryption architecture (Argon2id + AES-256-GCM + HMAC-SHA256) is quantum-resistant.**

```
┌──────────────────────────────────────┬──────────────────────────────────────┐
│ Asymmetric / Public-Key (Broken)     │ Symmetric & KDFs (Quantum-Resistant) │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ • RSA, ECC, ECDSA, Diffie-Hellman   │ • Argon2id, AES-256-GCM, SHA-256     │
│ • Broken by Shor's Algorithm        │ • Subject only to Grover's Algorithm │
│   (Polynomial-time algebraic break)  │   (Quadratic reduction: 256 -> 128)  │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

### Why Kist Envelopes Are Quantum-Safe:

1. **Immunity to Shor’s Algorithm:**
   Shor's algorithm compromises asymmetric cryptosystems (like RSA and elliptic curve cryptography) by solving discrete logarithms and prime factorizations in polynomial time. Argon2id, AES-256, and HMAC-SHA256 are purely symmetric, permutation-based constructions that do not rely on algebraic number theory. Shor's algorithm has zero applicability to Kist envelopes.

2. **Grover's Algorithm Resistance (128-Bit Security Margin):**
   Grover’s algorithm provides a quadratic speedup for unstructured brute-force search against symmetric ciphers, effectively halving the key space ($n \rightarrow n/2$). Because Kist uses **AES-256** (a 256-bit key), an attacker utilizing Grover’s algorithm still faces an effective complexity of **$2^{128}$ operations**. Breaking a $2^{128}$ search space remains computationally and physically infeasible under known physical and thermodynamic constraints.

3. **Memory-Hard Quantum Penalty:**
   Argon2id is explicitly memory-hard (requiring 64 MB RAM per evaluation). Implementing memory-intensive graph traversal on quantum hardware requires maintaining massive arrays of fault-tolerant, error-corrected qubits with enormous $T$-gate circuit depth. This imposes extreme financial and physical overhead per guess for any hypothetical quantum adversary.

4. **Algorithm Agility for Future Risk Mitigation:**
   Kist’s self-describing binary header explicitly records the KDF, cipher, and envelope version. If future cryptographic breakthroughs necessitate parameter migration or post-quantum algorithm transitions, the architecture accommodates seamless upgrades without invalidating legacy envelopes.

---

## 10. Summary of Rules for Users

1. **Initialize Explicitly:** Initialize your database schema with `kist init-db` or `store.init_db()` before locking secrets.
2. **Protect Profile Passwords:** Never commit `~/.kist/pwd_*` files or plaintext passwords to version control.
3. **Rely on Context Integrity:** A secret encrypted for `profile="staging"` cannot be decrypted under `profile="production"` even if both share the same master password.
4. **Check File Permissions:** Ensure the `.kist` directory is owned by your user and inaccessible to other system accounts.
5. **Enable TLS in Production:** Ensure PostgreSQL connections use TLS verification (`verify-full` or `verify-ca`) to prevent man-in-the-middle attacks.

---

## 11. Acknowledgments & Cryptographic Primitives

Cryptographic primitives (AES-256-GCM AEAD and Argon2id KDF) are powered by the standard Python Cryptographic Authority ([`cryptography`](https://github.com/pyca/cryptography)) library.
