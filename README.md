# py-sphincs-plus

This repository contains a Python implementation of the SPHINCS+ post-quantum signature scheme, developed for educational purposes.

## What is SPHINCS+?

SPHINCS+ is a stateless hash-based signature scheme that is designed to be secure against attacks by quantum computers. It is a candidate for standardization by the National Institute of Standards and Technology (NIST) in their Post-Quantum Cryptography Standardization project.

Key features of SPHINCS+:
* **Post-quantum secure**: Relies on the security of cryptographic hash functions, which are believed to be resistant to quantum attacks.
* **Stateless**: Unlike some other hash-based signature schemes, SPHINCS+ does not require maintaining state information, simplifying its deployment and reducing risks associated with state compromise.
* **Provably secure**: Its security can be formally reduced to the security of the underlying hash functions.

## Project Goals (Educational)

The primary goals of this implementation are:
* To deepen understanding of the SPHINCS+ algorithm and its underlying cryptographic primitives.
* To provide a clear, readable, and well-documented Python codebase that mirrors the structure and logic of the SPHINCS+ specification.
* To experiment with custom components (e.g., different hash functions, random number generators) within the SPHINCS+ framework.
* To explore the practical aspects of implementing post-quantum cryptographic schemes.

**Note**: This implementation is for educational and experimental purposes only and should **not** be used in production environments. It has not undergone rigorous security audits or extensive optimization for performance.

## Repository Structure

The project is organized as follows:

- [`spyncs_plus/`](spyncs_plus/): Main directory for the SPHINCS+ implementation.
  - [`spyncs_plus/sphincs_plus.py`](spyncs_plus/sphincs_plus.py): Core SPHINCS+ algorithm logic.
  - [`spyncs_plus/components/`](spyncs_plus/components/): Contains various cryptographic components used by SPHINCS+ (e.g., Winternitz signatures, Merkle trees, address generation).
  - [`spyncs_plus/helpers/`](spyncs_plus/helpers/): Helper functions and modules.
    - [`spyncs_plus/helpers/hashers/`](spyncs_plus/helpers/hashers/): Implementations of cryptographic hash functions.
    - [`spyncs_plus/helpers/random_generators/`](spyncs_plus/helpers/random_generators/): Modules for secure random number generation.
  - [`spyncs_plus/utils/`](spyncs_plus/utils/): Utility functions.
    - [`spyncs_plus/utils/password_protection/`](spyncs_plus/utils/password_protection/): (Placeholder/Example) Demonstrates potential integration of SPHINCS+ for password protection or similar applications.

## Getting Started

### Prerequisites

* Python 3.9+

### Installation

```bash
git clone https://github.com/your-username/py-sphincs-plus.git
cd py-sphincs-plus
pip install -r requirements.txt # (assuming a requirements.txt will be added later)
```

### Usage

(Examples will be added here once the core implementation is complete.)

```python
# Example: Key Generation
# from spyncs_plus.sphincs_plus import SPHINCSPlus
#
# sphincs = SPHINCSPlus(n=256, w=16, k=8, h=60, d=10, t=16) # Example parameters
# private_key, public_key = sphincs.generate_keypair()
#
# # Example: Signing
# message = b"Hello, SPHINCS+!"
# signature = sphincs.sign(message, private_key)
#
# # Example: Verification
# is_valid = sphincs.verify(message, signature, public_key)
# print(f"Signature valid: {is_valid}")
```

## Contributing

As this is an educational project, contributions are welcome, especially those that help clarify the implementation, improve documentation, or provide alternative component implementations for learning purposes.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* The NIST Post-Quantum Cryptography Standardization project.
* The SPHINCS+ specification and related academic papers.
* Cryptography communities and resources that facilitate learning and development.
