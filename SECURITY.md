# Security Model & Formal Specification

> **Status: this document describes the intended security properties of the
> `DeniableMulti` scheme as implemented in this repository (browser
> `crypto.js` + Python reference `multi_key/deniable_multi.py`).**
>
> ⚠️ **Read the disclaimer first.** This is a research/educational **proof of
> concept**. It has **not** been formally verified, indepently audited, or
> cryptanalyzed. Nothing here asserts a proof of security. See
> [README.md](README.md#proof-of-concept-not-production).

---

## 1. Notation

Let $\kappa$ be a security parameter (AES-256-GCM key $= 32$ bytes, tag $=16$ bytes,
nonce $=12$ bytes). Fix a slot-position field width $\mathbf{w}=2$ bytes and a
maximum-trial budget $\tau=32$.

A **container** $C$ is a byte string of length $\mathsf{total}$, where
$256 \le \mathsf{total} \le 2^{8\mathbf{w}}-1 = 65535$.

A **slot** for plaintext $m$ is
$\mathsf{slot} = \big[\; \mathsf{len}_{2}\;\big]\;\big[\;\mathsf{nonce}_{12}\;\big]\;\big[\;
\mathsf{AES\text{-}GCM}_{\;K_{enc}}(\mathsf{nonce},\; \mathsf{u32}(\lvert m\rvert)\,\Vert\,m\,\Vert\,\mathsf{pad},\; \mathsf{AAD}) \;\big]$,
where $\mathsf{pad}$ is uniformly random filler to the configured slot length.

For each key $k$ define two derived values via HKDF-SHA256 with 32 zero-byte salt:
$$\begin{aligned}
K_{enc} &= \mathrm{HKDF}(k,\; \mathsf{"m/enc"})\\
\mathsf{pos}(k,\mathsf{total},t) &= \big(\,\mathrm{HKDF}(k,\; \mathsf{"m/pos/"}\,\Vert\,\mathsf{total}_{\mathbf{w}}\,\Vert\,t_{2})\bmod \mathsf{total}\big)
\end{aligned}$$

---

## 2. Adversary model

### 2.1 Computational vs information-theoretic

The scheme is **computationally secure**, **not information-theoretically secure**.

* **Cryptographic hardening** rests on standard, concrete computational
  assumptions realized by the primitives: AES-GCM is expected to be
  **AES-256-GCM authenticated-encryption with nonce-respecting misuse
  resistance**, and HKDF-SHA256 is expected to behave as a **PRF** over its key
  input. Security holds only against **probabilistic polynomial-time (PPT)**
  adversaries and only insofar as these primitives are assumed sound.
* There is **no absolute/information-theoretic guarantee** of any sort. A
  computationally unbounded coercer who obtains the raw container $C$ and *all*
  plaintext/key candidates you ever considered is, in principle, not excluded
  by this document’s reasoning.

### 2.2 Privacy of the slot content

The plaintext $m$ is protected as **AES-256-GCM confidentiality**: a PPT
adversary who holds $C$ and the derived $K_{enc}$ but not $m$ cannot learn
$m$ (beyond its length and any padding), on the security of AES-GCM.

### 2.3 Integrity

Each plaintext carries a GCM 128-bit tag over ciphertext + AAD. A PPT
adversary cannot forge a slot that decrypts to a chosen plaintext without the
slot key, on the authenticity of AES-GCM. **Boundary:** only the *slot*
contents are authenticated; the *padding* between slots and the container
itself carry **no integrity**. A corrupting channel must be addressed upstream
(e.g., AAD bound to context, or a transport MAC).

---

## 3. Threat model — what the coercion resistance actually is

This scheme is built to resist **coercion** by an honest-but-curious **coercer**.
It does **not** aim to resist an adversary who may *choose* to extract every key
by force.

### 3.1 Coercer capability (the honest-but-curious coercer)

Define the coercer $\mathcal{C}$ by the following *assumed* capabilities and
limits. **This assumption — that $\mathcal{C}$ restricts itself as below — is
the load-bearing assumption of the whole scheme.** It is recommended, but
ultimately *your* operational judgment, that a given coercer meets it.

| # | The coercer… | Assumed limit |
|---|---|---|
| C1 | is PPT | cannot break AES-GCM / HKDF |
| C2 | captures the container $C$ | has $C$ fully |
| C3 | may force you to **reveal any strict subset** of your keys | **cannot** force all $N$ keys (a strict subset) |
| C4 | does **not** control the hidden portion ahead of time | does not know the true slot count $n \le N$ you hold, nor the positions/contents of unrevealed slots |
| C5 | observes your revealed keys and messages | does **not** independently learn the identity of "the real" message beyond what the ciphertext + revealed subset implies |
| C6 | may interrogate you round after round | each new reveal is still a strict subset; $\mathcal{C}$ never obtains every key at once |
| C7 | is **not** adaptive in the game-theoretic sense of renegotiating which messages are "real" | the set of candidate messages and their keys is fixed before coercion begins |

### 3.2 What the coercer does **not** gain

Given the revealed set $S \subsetneq K$ ($K$ the full key set):

1. **Cannot count the remaining slots.** Slot positions are
   $\mathsf{pos}(k,\cdot,\cdot)$ with $k$ unknown to $\mathcal{C}$. If HKDF is a
   PRF, $\mathcal{C}$ has no information about positions of slots whose keys are
   in $K\setminus S$; a slot position is indistinguishable from uniform among
   the $65536\wedge\mathsf{total}$ possible ones. Hence the **slot count $N$ is
   hidden** except for the lower bound $|S|$ that you reveal.
2. **Cannot tell which revealed message is "the" real one.** Even knowing $S$,
   all revealed slots look alike (in particular under `pad_to` they are uniform
   length) and are each a valid message; without the keys in $K\setminus S$ the
   coercer cannot distinguish your intended message from a cover.
3. **Cannot prove incompleteness.** Because unrevealed slots’ positions are
   uniform to $\mathcal{C}$, your claim "that is everything" cannot be refuted by
   inspecting $C$ and $S$ alone. (Equally: it also **cannot** be *verified* from
   $C$ and $S$ — see §3.3.)

### 3.3 What the coercer **does** learn — honest limits

* **Existence of at least $|S|$ slots and a magnitude bound.** A coercer holding
  the full container sees that it is non-empty random-ish data. To *deny the
  existence* of any hidden material you must be in a different scheme (the
  two-key "deny existence" variant); this N-key scheme explicitly **admits**
  multiplicity.
* **Container size leaks magnitude.** $\mathsf{total}$ is visible. A larger
  container with a small reveal is *itself* a signal that hidden material may
  exist. Use `pad_to` and a container size story consistent with the number of
  keys you reveal.
* **Total compromise under total key capture.** If $\mathcal{C}$ *violates* C3
  (obtains **all** $N$ keys), it decrypts everything. This scheme protects
  against *selective* coercion, not against rubber hoses applied to all $N$.

### 3.4 The property being claimed: *deny completeness, not existence*

We do **not** claim information-theoretic or even computational *non-interference*
against a coercer who forces total key disclosure. The claimed property is
narrow and precise:

> **Completeness-deniability (informal).** For any revealed strict subset of keys
> $S$, the distribution of the container $C$ together with $S$ is (computationally)
> indistinguishable from one in which you held exactly the slots of $S$ — provided
> the unrevealed keys $K\setminus S$ are uniformly random and independent, the slot
> count is not forced, and the coercer is PPT and honest-but-curious.

This mirrors the *completeness* (not *existence*) denial goal of the parent
project’s threat-model note ("admit others exist, deny it's all / deny identity").

---

## 4. Formal specification of the algorithms

### 4.1 Key parsing (`parseKey`)

Given a string $s$ and selected bit-length $b \in \{16,32,64,128,256,512\}$,
define $\mathsf{key}(s,b)$ concretely:

* if $b=256$ and $s$ is a 64-char hex string → **decoded 32-byte key**;
* else if $s$ is a hex string of length exactly $b/4$ → **decoded $b/8$-byte key**;
* else → the **UTF-8 bytes** of $s$.

Every distinct string yields a distinct key *except* the intentional hex-decode
cases, so ciphertexts made with generated 64-hex keys remain byte-compatible with
the Python reference. The scheme object itself is key-length-agnostic: any derived
$K_{enc}$ is 32 bytes from HKDF, so *strength* follows from the entropy of $k$,
and *parsing* depends on $s,b$ only.

### 4.2 Encrypt

$$
\mathsf{Enc}(M_{1..N}, K_{1..N}; \mathsf{size}, \mathsf{pad\_to}, \mathsf{AAD})
$$
1. validate $N=\lvert M\rvert=\lvert K\rvert\ge1$, keys distinct;
2. for each $i$: $K_{enc}^{(i)}=\mathrm{HKDF}(k_i,\mathsf{"m/enc"})$;
3. build plaintext $p_i=\mathsf{u32}(\lvert m_i\rvert)\Vert m_i$; if $\mathsf{pad\_to}$
   set, $p_i \mathrel{+}= \mathrm{rand}(\mathsf{pad\_to}-\lvert p_i\rvert)$;
4. compute $\mathsf{ct}_i=\mathsf{AES\text{-}GCM}_{\,K_{enc}^{(i)}}(\mathsf{nonce}_i, p_i, \mathsf{AAD})$;
5. choose $\mathsf{total}$ (explicit $\mathsf{size}$, or auto $=\mathrm{max}(\sum|\mathsf{slot}_i|,256)\cdot4+\mathrm{jitter}$, rounded up to 256);
6. $C \leftarrow \mathrm{rand}(\mathsf{total})$;
7. for each $i$ in order, for $t=0..\tau{-1}$ recompute
   $p=\mathsf{pos}(k_i,\mathsf{total},t)$ until no overlap with already-placed
   slots; write the slot; if $\tau$ trials all collide → **abort**.

### 4.3 Decrypt

$\mathsf{Dec}(C, k; \mathsf{AAD})$: derive $K_{enc}$, then for $t=0..\tau{-1}$:
pos $=\mathsf{pos}(k,\mathsf{total},t)$; read candidate slot at that offset; if
the length-prefix is sane and $\mathsf{AES\text{-}GCM}$ verifies under $\mathsf{AAD}$
→ output the $\mathsf{u32}$-length-prefixed plaintext; else continue. Return
`None` if no trial succeeds.

**Worst-case cost:** a *wrong* key performs up to $\tau=32$ GCM verification
attempts before returning `None`. This is the only per-decrypt work that scales
with $\tau$; see Benchmarks.

---

## 5. Placement: correctness & the true capacity ceiling

* **Correctness.** Overlap resolution with $\tau=32$ trials and wrap-around
  buffer I/O guarantees every slot is recoverable by its own key, **independent
  of $N$** — a key never needs to know how many slots exist.
* **Real capacity: position-space ceiling, not just file-size ceiling.**
  Because $\mathbf{w}=2$, $\mathsf{pos}\in[0,\mathsf{total})$ but the *PRF output
  width* is $16$ bits, so positions are effectively drawn from a
  $2^{16}=65536$-sized space regardless of $\mathsf{total}$. Once a slot’s byte
  length rivals that $65536$ range, the probability that 32 random positions
  avoid overlap collapses and the **encrypt aborts with "all positions
  collide"** (observed in practice at ~4 KiB/slot with $N=4$). **Practical
  ceiling: containers of a few tens of KiB and per-slot messages of a few KiB.**
  Raising requires `pos_bytes=4` (a subclass), which **changes positions and
  breaks every existing ciphertext**.

---

## 6. Known limitations & attack surface (honest list)

These are **not** hypotheticals; several are directly observable in this code.

1. **PoC, not audited.** No formal verification, no independent audit, no
   cryptanalysis track record. Do not use for real data.
2. **Non-constant-time exposure / metadata.** The 16-bit slot-position space is
   unusually small for a real scheme; a PPT coercer who (wrongly hypothesizes) a
   slot can enumerate all $65536$ candidate positions in §5’s space with trivial
   effort. In practice this only matters if it can also test GCM, which needs a
   key — so the practical attack is limited, but the **position space is a
   design smell** worth flagging.
3. **Size leak.** $\mathsf{total}$ is public.
4. **No container integrity.** Only slots are authenticated.
5. **RNG cap in the browser build.** `crypto.js` fills the whole container with a
   **single** `crypto.getRandomValues` call; WebCrypto caps one call at **65536
   bytes**. A container $\ge$ that size **throws `QuotaExceededError`** in the
   browser build (confirmed under Node). Combined with the position ceiling this
   means the UI cannot practically produce containers above ~64 KiB today.
6. **Key-strength dependence.** A custom string key is only as strong as the
   string; the GCM tag is a **verification oracle** for dictionary attacks. The
   UI already warns, but this does not make short passphrases safe.
7. **Fixed HKDF salt.** The headerless design forces $\mathrm{salt}=\mathsf{0}^{32}$
   (literal zero). HKDF with a zero salt and variable per-key info is acceptable
   under HKDF’s model, but it removes one layer of domain separation that a
   salted design would provide.
8. **Same-key reuse ⇒ collision of reality.** Two slots cannot share a key
   (rejected at encrypt); reusing `pad_to` mis-specified can make covers
   identical and thus less deniable.
9. **Traffic/plausibility.** The number of keys you *carry* and their apparent
   uses must be plausibly explainable; the container itself leaks magnitude.

---

## 7. Comparison to the literature (honest, non-quantitative)

Claims here are **qualitative**; we do **not** produce comparative micro-metrics
against CDNR97 or other constructions, because (a) this is a PoC with no audited
reference, and (b) "StegoED" could not be located as a well-defined published
scheme. See [BENCHMARKS.md](BENCHMARKS.md) for our own measured numbers.

| Property | This scheme (N-key, headerless) | CDNR97 parity / multi-prover (CRYPTO ’97) |
|---|---|---|
| Deniability target | completeness / identity (admit existence) | existence/identity of the real bit, via exculpatory randomness |
| Adversary bound | PPT, honest-but-curious coercer, strict-subset key reveal | PPT coercer; receiver-faking uses extra rounds of communication |
| Per-bit overhead | N/A — operates on whole messages, one GCM per message | parity scheme encodes **per bit** as $n$ set elements (large expansion) |
| Faking | reveal a strict subset of keys; no extra rounds | sender reveals "wrong" randomness; multi-prover needs extra comms round |
| Basis | standard model-ish primitives (AES-GCM, HKDF) | CDNR97 construction relies on translucent sets / trapdoor functions |
| Maturity | PoC, unverified | peer-reviewed foundational scheme (but inefficient & not deployed) |

The material claim is narrow: for the *specific* honest-but-curious coercer
model above (C1–C7) and the *specific* completeness-denial goal, this N-key
construction has low constant-time overhead (one GCM + HKDF per slot, see
BENCHMARKS.md) compared to bit-expanding CDNR-style constructions. We make **no
claim** of matching the formal security guarantees of a peer-reviewed, audited
scheme.

---

## 8. Threat model cheat-sheet

| Coercer wants… | You do… | Result |
|---|---|---|
| "Show me what's inside" | reveal only cover keys (strict subset) | coercer sees plausible cover; cannot count/verify the rest |
| "Is there more?" | deny | cannot be refuted (nor verified) by $C$ + $S$ |
| "I'll take all your keys" | — | **everything falls.** This scheme does **not** help against total key seizure |
| "Explain this big container" | give a size-consistent story | size itself leaks magnitude; plan `pad_to`/size for the story |

**Bottom line:** use this only if your real threat is a *partial-key* coercer who
relents at a strict subset, and never for data where total key seizure is
credible.
