# Licence verification keys

Public keys used to verify NERvvE DevSecOps licence keys, one PEM file per key id (`<kid>.pem`).
Create the vendor key with `python scripts/licensing/myelin_license.py keygen --kid <kid> --out <path outside repo>`;
it writes the public half here. Commit it and release — only then do products accept licences signed with that key.
Keep old public keys when rotating so earlier licences stay valid until they expire.
The private keys are never stored in this repository.
