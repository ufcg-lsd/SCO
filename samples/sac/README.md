# SGX install

This project contains a single file for installing SGX driver and SDK/PSW latest version on an SGX capable and enabled machine.

## Cloning and configuring

```bash
git clone https://<username>@git.lsd.ufcg.edu.br/secure-cloud/sgx-install.git
cd sgx-install
chmod +x install_sgx_latest.sh
```

## Installation

To install it, simply run the following command:

```bash
sudo ./install_sgx_latest.sh
```

If you want to allow the heap to be executable, you should run the following command:

```bash
sudo ./install_sgx_latest.sh -xh
```
