"""
crypto — AES mode implementations.

Modules
-------
ecb : AES-ECB (Electronic Codebook) — insecure baseline only.
cbc : AES-CBC (Cipher Block Chaining) — confidentiality, no integrity.
ctr : AES-CTR (Counter Mode) — confidentiality, fully parallelisable.
gcm : AES-GCM (Galois/Counter Mode) — AEAD (confidentiality + integrity).
"""
