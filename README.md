# Mesh Infrastructure

## Overview

The Mesh is a global information infrastructure that allows software "Agents" to securely communicate with each other, and form a global, cryptographically secure, information space across the internet.  It relies on Confidential Computing to attest and verify that the software of each Agent hasn't been compromised, as well as that no keys or secrets have been exposed outside "Trusted Execution Environments", or TEEs. Agents rely on "TrusTEEs", another type of Mesh actors that secure/store/fetch data on Agents' behalf, and help establish secure connections between Agents.

This infrastructure leverages [Intel SGX](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html) Confidential Computing technology to attest and verify all hardware and software actors in the Mesh. When running software in SGX TEEs, we have taken the approach to limit the calls TEEs can make outside their secure boundaries (OCALLs).  This prevents unwanted call to operating system functions that could leak data. To enable this, all Rust crates that Agents use are Rust no_std so that they have no system calls. The libraries and dependencies in this repository for building an Agent are no_std.

This repository contains the crates needed to create a Mesh Agent, along with an example of an Agent. The sample Agent is a VDR Agent (Verifiable Data Registry), one of the Mesh actors involved in an implementation of the three-party model (Issuer - Holder - Verifier). The repository does not contain the source code for TrusTEEs that Agents rely on, nor the "Factory Agent" that is used to build other Agent TEEs and register them in the Mesh. Please contact Hushmesh at info at hushmesh.com for more information about running and deploying Agents that you can build with the crates provided here.

## Background

These libraries were developed as part of the "Privacy Preserving Digital Credential Wallets & Verifiers" topic call administered by the Department of Homeland Security (DHS) Science and Technology Directorate (S&T) Silicon Valley Innovation Program (SVIP). [More information about this topic call can be found here](https://www.dhs.gov/science-and-technology/hushmesh).

They are grouped into the following categories:

* OSL (A) – Cryptographic Tools 
  * The Mesh leverages [wolfssl](https://github.com/wolfSSL/wolfssl) for it cryptographic functions.   We have created wrapper functions that are in [crate-common-crypto](#cryptography-library) for this functionality.
* OSL (B) - Sealed Storage
  * The library that provides the API to Agents is called [crate-common-agent](#agent-sdk).  It provides data operations that are used to store and retrieve data in the Mesh.  The data is encrypted with keys that never leave TrusTEEs.
* OSL (C) - Metadata Management
  * The [actor-vdr-agent](#vdr-actor) is an Agent that is included in this repository.  It provides an API in the Mesh to create DIDs using the [did:web](https://w3c-ccg.github.io/did-method-web/) method. It creates and stores the DID documents for those DIDs and provides an API to retrieve them. This is an Agent we used for our Holder Agent (i.e. our Mesh Wallet) but it can be reused for any Agent running in the Mesh.
* OSL (D) – Confidential Computing
  *  The Agent library [crate-common-agent](#agent-sdk) provides the API for the Agents to connect to their Agent TrusTEE. During that connection, attestation is performed such that, if the TrusTEE cannot verify the software the Agent is running, the Agent will not be allowed to perform additional functionalities such as retrieving and processing data.
* Additional libraries
  * [crate-common-verifiable-credentials](#verifiable-credentials-library) provides functions for building and parsing Verifiable Credentials and Verifiable Presentations.  It is also contains functions for creating derived BBS proofs. It is used by the Agents we built such as the VDR Agent.

## Repository libraries

This repository is divided into Actors and Crates.
* Actors
  * Actors are Agents that provide services to other Agents in the mesh.  Each Actor is compiled as a library.  When built using the Mesh Factory Agent, it becomes an SGX signed shared object that is loaded into TEEs in the Mesh.  All Actors are no_std.
* Crates
  * Crates are libraries that provide functions to Actors
  * Crates beginning with the prefix crate-common- are no_std crates that can be used in SGX TEEs
  * Crates beginning with the prefix crate-app- are intended only for application utilities that do not run in TEEs.  An example of this is crate-app-build-data that is used as part of the build process to create unique IDs for each Agent that are injected into the code at build time.

## Crates

### Agent SDK
* [crate-common-agent](./crates/crate-common-agent/)
* This is the library that has all the functions an Agent uses.  This includes the following:
  * Connecting to its Agent TrusTEE to establish an secure connection to the Mesh network
  * API to store and retrieve data in Mesh cell storage. Cell storage is a type of key-value pair storage where all data is encrypted with unique keys derived from
    a unique TrusTEE identifier (StemID).
  * Establishing connections between Mesh entities (e.g. human to wallet) so encrypted messages can be sent between those entities.
  * Managing relationships and permissions between Mesh entities to determine how they are allowed to interact with each other.
* See the [library documentation](#library-documentation) for more detail.

### Cryptography Library
* [crate-common-crypto](./crates/crate-common-crypto/)
* This is the library that has the cryptographic functions that the Mesh Agents and TrusTEEs use.  This includes the following:
  * Generating true random 256 bit values
    * The intel RDSEED function is used for this.
  * SHA256/SHA384/SHA384 function
     * [wolfssl](https://github.com/wolfSSL/wolfssl) is used for this.
  * AES GCM encryption and decryption
     * [wolfssl](https://github.com/wolfSSL/wolfssl) is used for this.
  * ECDSA signature generation and verification
     * [wolfssl](https://github.com/wolfSSL/wolfssl) is used for this.
  * BBS+ signature generation and verification
     * [bls12_381_plus](https://github.com/mikelodder7/bls12_381_plus) and [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium) are used for this.

### Messages Libraries 
* [crate-common-messages](./crates/crate-common-messages/)
* [crate-common-messages-verifiable-credentials](./crates/crate-common-messages-verifiable-credentials/)
* [crate-common-messages-web](./crates/crate-common-messages-web/)
* These libraries define messages that are sent in the Mesh.  Agents communicate with their Agent TrusTEEs and other Agents using Mesh messages (or "meshages").
  A Mesh message includes a header used for routing.   The message struct definitions define the API contracts.  Messages are serialized and deserialized
  in the Mesh using [CBOR](https://cbor.io/).

### Verifiable Credentials Library
* [crate-common-verifiable-credentials](./crates/crate-common-verifiable-credentials/)
* This library contains functions for processing [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) and Presentations.
  This includes the following:
  * Building the hash of a JSON-LD document needed for ecdsa-rdfc-2019 signatures
  * Building the hash of a JSON-LD document needed for BBS+ signatures
  * Verifying the credential in a JSON-LD document
* The crate [json-ld](https://github.com/timothee-haudebourg/json-ld) and its dependencies are leveraged by this library.  We forked them to create no_std versions.

### Common Type and Utilities Libraries
* [crate-common-types](./crates/crate-common-types)
* [crate-common-enclave-process](./crates/crate-common-enclave-processor)
* [crate-common-sessions](./crates/crate-common-sessions/)
* [crate-common-async](./crates/crate-common-async/)
* [crate-common-sync](./crates/crate-common-sync/)
* [crate-app-build-data](./crates/crate-app-build-data/)
* [crate-common-build-injection](./crates/crate-common-build-injection/)
* These libraries are common building blocks used by the above libraries. They include common types as well as functions to use Rust async within 
  TEEs without having to require a full runtime that makes operating system calls such as tokio.

## Actors

### VDR Actor
* [actor-vdr-agent](./actors/actor-vdr-agent)
* The API definition is defined by these [messages](./crates/crate-common-messages-verifiable-credentials/src/vdr_agent_messages.rs)
* Those messages provide the following functionality:
  * Creating a new unique DID id (using did:web method) and storing the DID document for it in encrypted Mesh cell storage.
  * Creating a private key for the DID.
  * Fetching the DID document so it can be exposed via a Web URL.

## Building

The makefile is used to build the libraries:
* make all
  * Builds the VDR Agent library and its dependencies
* make test
  * Runs tests on the crates
* make clean
  * Remove libraries from build

Note: Contact Hushmesh for information about running Agents in the Mesh at info at hushmesh.com

## Dependencies

The libraries and actors above depend on the following open source libraries:
* [json-ld](https://github.com/timothee-haudebourg/json-ld)
  * We forked it and its dependencies to add no_std support.  There are available [here](https://github.com/hushmesh/json-ld-nostd.git).
* [bls12_381_plus](https://github.com/mikelodder7/bls12_381_plus)
  * We forked it [here](https://github.com/hushmesh/bls12_381_plus) and have submitted changes to the upstream.
* [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium)
  * We forked it [here](https://github.com/hushmesh/zkryptium) and have submitted changes to the upstream.
* [wolfssl](https://github.com/wolfSSL/wolfssl)

## Library Documentation

Documentation for the function definitions for the above libraries has been automatically generated and is provided [here](https://hushmesh.github.io/mesh-infrastructure/common_agent/index.html).

## License

These libraries are published under the [Apache License Version 2.0](./LICENSE).
