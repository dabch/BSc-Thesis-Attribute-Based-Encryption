# Implementation of Attribute-Based Encryption in Rust on ARM Cortex-M Processors
Bachelor's Thesis by Daniel Bücheler

## Repository structure
- `abe-utils/`: library crate with common functionality of ABE schemes, i.e. access trees, symmetric crypto (key encapsulation mechanism) and policies for evaluation
- `gpsw06-abe/`: library crate with implementation of the Goyal, Pandey, Sahai and Waters KP-ABE scheme from 2006
- `nrf52840-evaluation/`: binary crate used to evaluate the library on the nRF52840 SoC
- `presentation/`: TeX and PDF of the thesis presentation
- `thesis/`: TeX and PDF of the thesis itself (shortlink: [THESIS](thesis/build/main.pdf))
- `x86-evaluation/`: binary crate used to evaluate the library on the laptop
- `yct14-abe/`: library crate with implementation of the Yang, Chen and Tian pairing-free KP-ABE scheme from 2014
- `test_policy_generator.py`, `deep_policy_generator.py`: Python helpers used to generate the test policies in [abe-utils/src/test_policies.rs](abe-utils/src/test_policies.rs)
