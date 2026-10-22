# Kist Encryption 101

A clear, practical guide to how Kist protects secrets, why every piece exists, and how the underlying cryptography ensures maximum safety with minimum operational friction. For the exact byte layout and the compatibility promise, see [FORMAT.md](FORMAT.md).

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
| **Key Encryption Key (KEK)** | 256-bit AES Key | The master vault key | Derived via Argon2id from the password; only ever wraps random keys: the data key of a Git file, or the database key bundle. |
| **Key Bundle** | `_KeyBundle` (Content + Index Keys) | The inner safety-deposit key ring | Contains two randomly generated 256-bit keys: a **Data Encryption Key (DEK / `content_key`)** and a **Blind Index Key (`index_key`)**. |
| **Data Encryption Key (DEK)** | 256-bit AES Key | The swift everyday safety deposit key | Directly encrypts individual secret payloads in PostgreSQL with AES-256-GCM in microseconds without repeating expensive Argon2id derivations on every read. |
| **Index Key** | 256-bit HMAC Key | The blind catalogue encoder | Derives 32-byte deterministic HMAC-SHA256 lookup tokens so database queries find secrets without leaking plaintext secret names. |
| **Nonce / IV** (12 bytes) | Initialization Vector | A single-use random lock serial number | Guarantees that encrypting the exact same secret twice results in completely different ciphertext. |
| **Encryption Engine** | AES-256-GCM | An armored box with a tamper-evident seal | Encrypts the payload (confidentiality) and computes a 16-byte authentication tag (integrity). |
| **Context / AAD** | Authenticated Additional Data | The indelible shipping label glued to the box | Binds ciphertexts to their exact organization, project, profile, key, and version so attackers cannot swap or transplant records. |
| **Envelope** | Password envelope, format version 1 | The final sealed shipping parcel | The standardized binary package containing header metadata, salt, nonces, context hash, the wrapped data key, and ciphertext ([FORMAT.md](FORMAT.md)). |

---

## 3. Two-Tier Envelope Architecture (KEK / DEK)

Both Git files and the database use two tiers: the slow, password-derived key (KEK) only ever wraps random keys, and random keys encrypt the actual content. The exact bytes are specified in [FORMAT.md](FORMAT.md).

### A. Git Secret Files (`kist-git-v1`)
For Git-managed files (`secrets/<profile>.yaml`, `secrets_<profile>.yml`, …), each file is one **password envelope**:
```
[Profile Password] + [Fresh 16-byte Salt]
               │
               ▼ (Argon2id: 64 MiB RAM, 2 iterations, 4 lanes)
       [32-byte KEK (wrapping key)]
               │
               ▼ (AES-256-GCM, fresh 12-byte nonce)
[Fresh random 32-byte data key] ──> [Wrapped data key + 16-byte tag]

[Whole YAML file] + [Fresh 12-byte nonce] + [Git context (org/project/profile/repository/path)]
               │
               ▼ (AES-256-GCM with the data key)
   [Ciphertext + 16-byte tag]
               │
               ▼
   [Header || wrapped data key || nonce || ciphertext]
```

### B. PostgreSQL Database Storage
In PostgreSQL, individual secret reads (`store.get(...)`) occur frequently at application runtime. Running a 64 MiB Argon2id key derivation on every single read would introduce unacceptable latency, so the password unlocks a **key bundle** once, and secrets use its fast keys:

```
1. UNWRAPPING THE KEY BUNDLE (once per load):
[Profile Password] + [kist_key_bundles.wrapped_bundle (a password envelope)]
               │
               ▼ (Argon2id KEK derivation, AES-256-GCM unwrap, as for Git files)
   [Key Bundle: "KKB1" || content key (32 bytes) || index key (32 bytes)]

2. RETRIEVING & DECRYPTING A SECRET (microseconds):
   [Secret name + scope] + [Index Key] ──> HMAC-SHA256 ──> [32-byte lookup token]
                                                                 │
                                                                 ▼ (query DB)
                                                      [kist_secrets row]
                                                                 │
                                                                 ▼ (AES-256-GCM with the content key)
                                                 [{"key": name, "value": secret}]
```

1. **Key Bundle Wrapping:** a random 256-bit `content_key` and 256-bit `index_key` are generated once per profile and stored in `kist_key_bundles`, inside a password envelope.
2. **Secret Payload Encryption:** each row of `kist_secrets` holds the secret's name and value, encrypted together with the `content_key` and bound to its row, bundle, lookup token and version.
3. **Blind Indexing:** plaintext secret names are never stored; rows are found by a 32-byte HMAC-SHA256 token computed with the `index_key`.

---

## 4. Context & Authenticated Additional Data (AAD)

To prevent "ciphertext transplant" attacks (for example copying an encrypted record from a development environment into production, or one secret file over another), every encryption is bound to a JSON **context**, encoded canonically (sorted keys, no spaces). A ciphertext only opens with exactly the same context. The four contexts, exactly as the code builds them:

### 1. Database Secret Record (`kist-db-record-v1`)
```json
{
  "format": "kist-db-record-v1",
  "organization_id": "018f23a1-...",
  "project_id": "018f23a1-...",
  "profile_id": "018f23a1-...",
  "row_id": "018f23a3-...",
  "bundle_id": "018f23a2-...",
  "lookup_token": "9c1e...(64 hex characters)",
  "secret_version": "3",
  "crypto_version": "1"
}
```

### 2. Blind Lookup Token (`kist-name-index-v1`)
The HMAC-SHA256 input, keyed with the index key:
```json
{
  "format": "kist-name-index-v1",
  "organization_id": "018f23a1-...",
  "project_id": "018f23a1-...",
  "profile_id": "018f23a1-...",
  "secret_key": "third_party.stripe.api_key"
}
```

### 3. Key Bundle (`kist-db-key-bundle-v1`)
```json
{
  "format": "kist-db-key-bundle-v1",
  "organization_id": "018f23a1-...",
  "project_id": "018f23a1-...",
  "profile_id": "018f23a1-...",
  "bundle_id": "018f23a2-...",
  "bundle_version": "1",
  "access_mode": "password-wrap-v1"
}
```

The database contexts use the random UUIDs of the organization, project and profile rows, so ciphertext cannot be moved to another database, profile or row.

### 4. Git Secret File (`kist-git-v1`)
```json
{
  "format": "kist-git-v1",
  "organization": "local",
  "project": "default",
  "profile": "production",
  "repository": "local-repository",
  "path": "secrets/production.yaml"
}
```
`organization`, `project` and `repository` come from `KIST_ORG_ID`, `KIST_PROJECT_ID` and `KIST_REPOSITORY_ID` (defaults shown). `kist share` files use `{"format": "kist-share-v1", "profile": "<profile>"}`, without path or scope, so they open anywhere.

---

## 5. Inside the Kist Binary Envelopes

### A. Password Envelope
Used for Git files, `kist share` files and database key bundles (offsets in bytes):

```
+-------------------------------------------------------------------+
|  0  Magic "KIST" (4) | 4 Version 0x01 | 5 Cipher 0x01 (AES-256-GCM) |
|  6  KDF 0x01 (Argon2id) | 7 Flags 0x00                             |
+-------------------------------------------------------------------+
|  8  Argon2 memory, KiB (uint32, e.g. 65536)                        |
| 12  Argon2 iterations (uint32, e.g. 2)                             |
| 16  Argon2 lanes (uint16, e.g. 4)                                  |
+-------------------------------------------------------------------+
| 18  Salt (16, random)                                              |
| 34  Wrap nonce (12, random)                                        |
| 46  SHA-256 of the context (32)                                    |
+-------------------------------------------------------------------+
| 78  Wrapped data key (32 + 16-byte tag)                            |
|126  Content nonce (12, random)                                     |
|138  Ciphertext + 16-byte tag (variable)                            |
+-------------------------------------------------------------------+
```

The first 78 bytes (the header, including the Argon2 settings) are authenticated by both AES-GCM layers. Readers refuse unknown versions and Argon2 settings outside safe limits (memory 19 MiB to 256 MiB), so a hostile file cannot exhaust memory.

### B. Database Secret Record
Column `kist_secrets.encrypted_blob`:

```
+-------------------------------------------------------------------+
|  0  Magic "KSTR" + version 0x01 (5)                                |
|  5  Nonce (12, random)                                             |
| 17  AES-256-GCM ciphertext of {"key": ..., "value": ...} + tag     |
+-------------------------------------------------------------------+
```

The record carries no context hash: its context (section 4.1) is rebuilt from the row's own columns and authenticated by AES-GCM.

---

## 6. How Decryption Works

When an application retrieves a secret (`store.get("stripe.api_key")`, or `kist unlock` for a whole profile):

```
1. UNWRAP KEY BUNDLE
   Fetch wrapped_bundle from kist_key_bundles
   Check header, context hash and Argon2 limits
   Derive KEK via Argon2id(password, salt from the header)
   AES-256-GCM unwrap data key, then decrypt -> (content_key, index_key)

2. COMPUTE BLIND LOOKUP TOKEN
   lookup_token = HMAC-SHA256(index_key, name context)

3. FETCH & DECRYPT SECRET RECORD
   SELECT ... FROM kist_secrets WHERE profile_id = %s AND lookup_token = %s
   AES-256-GCM decrypt encrypted_blob with content_key and the record context

4. VALIDATE THE PAYLOAD
   Payload must be exactly {"key", "value"}
   Recompute the lookup token from the decrypted name; compare in constant time
   Return the value
```

If the password is wrong, the scope does not match, or any byte has been altered, Kist fails closed and raises `DecryptionError`.

---

## 7. Database Hierarchy & Schema

Kist structures PostgreSQL storage into an isolated relational hierarchy:

```
kist_organizations
    └── kist_projects
            └── kist_profiles
                    ├── kist_key_bundles (wrapped content & index keys)
                    └── kist_secrets     (HMAC lookup tokens & encrypted payloads)
```

### Schema Guarantees:
1. **No Plaintext Secret Names:** names (like `stripe.secret_key`) are never stored in database columns or sent as query parameters; lookups use 32-byte HMAC tokens. Organization, project and profile names are stored in clear.
2. **Versioned Records:** every write increments `secret_version`, and the version is bound to the ciphertext. This does **not** prevent rollback: someone who can write to the database can restore an older row as a whole. Kist has no rollback protection and no proof that the set of rows is complete.
3. **Transaction Advisory Locking:** writes take a PostgreSQL advisory lock (`pg_advisory_xact_lock`) scoped to the profile, with automatic retries, so concurrent writers cannot interleave.
4. **Rotation Isolation:** `kist profile rotate` re-encrypts all rows of a profile under `SELECT ... FOR UPDATE`.
5. **Real-Time Cache Synchronization:** writes send PostgreSQL `NOTIFY kist_secret_updated`, allowing runtime stores (`DynamicSecretStore`) to invalidate in-memory caches.

---

## 8. Password Management & Storage Security

Kist avoids storing passwords or plaintext keys in unsecured locations:

* **Local password Files (`~/.kist/pwd_<profile>`):**
  - Enforces strict POSIX permissions (`0600` on password files, `0700` on directory).
  - Prohibits symlinks to prevent symlink traversal attacks.
  - Generates 32-byte high-entropy URL-safe passwords via `kist profile create <name>`.
* **Environment Variables:**
  - `KIST_PASSWORD_<NAME>` (profile-specific, recommended for CI/CD).
  - `KIST_PASSWORD` (generic fallback, used only when no profile-specific password exists).

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
   Kist’s binary header records the envelope version, cipher and KDF. A future format would get a new version number while Kist keeps reading version 1 (see the compatibility promise in [FORMAT.md](FORMAT.md)); `kist profile rotate` re-encrypts everything with the current format.

5. **The Password Is the Limit:**
   All of the above assumes a strong profile password. Passwords generated by `kist profile create` carry 256 bits of entropy; a short human-chosen password is the weakest link, quantum or not.

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
