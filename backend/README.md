# Verifiable Credentials Backend

This is the backend service for the Verifiable Credentials application. It is built with Spring Boot and Java, and implements the W3C Verifiable Credentials Data Model v2.0 (VCDM v2.0).

## Features

- **VC Issuance & Verification**: Supports issuing credentials for multiple issuer types (University, Government, Medical, Telecom).
- **Securing Mechanisms**:
  - `bbs-2023`: JSON-LD VC with embedded BBS+ DataIntegrityProof (supports unlinkable derived selective-disclosure proofs).
  - `eddsa-jcs-2022`: JSON-LD VC with embedded Ed25519 DataIntegrityProof.
  - `sd-jwt-vc`: Wrapped in an EnvelopedVerifiableCredential for selective disclosure.
- **Revocation**: Uses Bitstring Status Lists to manage credential revocation (`BitstringStatusListEntry`).
- **Selective Disclosure**: Pre-computes predicate claims (e.g., age bounds) allowing holders to prove statements without disclosing underlying sensitive attributes like Date of Birth.

## Tech Stack

- **Java**
- **Spring Boot**
- **Maven**
- **Jackson** for JSON-LD / JSON processing

## Getting Started

### Prerequisites

- Java 21 or higher
- Maven (or use the included wrapper)

### Running Locally

To run the application locally using the Maven wrapper:

```bash
# Navigate to the backend directory
cd backend

# Run the Spring Boot application
./mvnw spring-boot:run
```

The application will typically start on port 8080 (or the port defined in `application.properties`). If the frontend is built, it may serve the frontend assets from `src/main/resources/webapp/`.

### Building

To build the executable JAR file:

```bash
./mvnw clean package
```

The resulting JAR will be located in the `target/` directory.

## Architecture

- **Controllers**: Handle HTTP requests from the frontend or direct API calls.
- **Services**: Core logic resides here (e.g., `IssuerService` for credential issuance).
- **Crypto / Proof Services**: Sub-packages dedicated to signing, proving, and verifying signatures using various schemes (`BlsKeyService`, `Ed25519KeyService`, `DataIntegrityBbs2023`, etc.).

