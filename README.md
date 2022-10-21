# SecureSC, a Ethereum Smart Contract Front-Running Vulnerability Detector

## Features

* Detects vulnerable Solidity code with low false negative rate and low false positives.


## Bugs and Optimizations Detection


Run SecureSC on a single file:
```bash
slither-dev test.sol
```

### Integration

Use [solc-select](https://github.com/crytic/solc-select) if your contracts require older versions of solc.

### Detectors

## How to install

SecureSC requires Python 3.8+ and [solc](https://github.com/ethereum/solidity/), the Solidity compiler.

### Using Git

```bash
git clone https://github.com/saner2023-securesc/SecureSC.git && cd SecureSC
python3 setup.py install
```