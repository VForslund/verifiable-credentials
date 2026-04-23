# Verifiable Credentials

Welcome to the Verifiable Credentials project. This workspace provides a full-stack implementation of Verifiable Credentials, enabling the issuance, holding, and presentation of digital identity claims.

## Project Structure

This repository is divided into two main components:

* **`backend/`**: A Java-based backend application managed with Maven. It handles core cryptographic operations, credential issuance, and verification processes.
* **`front/`**: An Angular-based web application that provides the user interface for credential management and presentation.

## Known Limitations

**Important Note:** The BBS signature implementation is currently not perfect because it hasn't fully implemented derived proofs. Selective disclosure functionality relying on these proofs is a work in progress.

## References

* Refer to the included `VerifiableCredentialsDataModelv2.0.pdf` for details on the overarching document structure and W3C standard compliance.
* Check the individual `README.md` files in the `backend/` and `front/` directories for localized setup instructions.

