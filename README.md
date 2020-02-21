K3 Image Signing Tool
=====================

K3 Image Signing Tool is intended to be one tool for signing/encrypting
various images used across the K3 software stack.

| Image                     | Status        |
|---------------------------|---------------|
| SBL Standalone Image      | Supported     |
| SBL Combined Image        | Supported     |
| SYSFW Inner Certificate   | In Progress   |
| SYSFW Outer Certificate   | Planned       |


| Image               | Status    |
|---------------------|-----------|
| Secure Boot         | Planned   |
| Debug Unlock Cert   | Planned   |
| In place auth       | Planned   |

Encryption Support is planned.

Installation
------------

1. Clone the repository.

    ```bash
    $ git clone https://github.com/TexasInstruments/k3sign.git
    ```
    or

    ```bash
    $ git clone git@github.com:TexasInstruments/k3sign.git
    ```

2. Install the tool.

    ``` bash
    $ cd k3sign
    $ python3 setup.py develop --user
    $ k3sign --help
    ```

Usage
-----

### Sign SBL and SYSFW for the combined image format

``` {.bash}
$ k3sign.py sbl-v2 --sbl dmsc_r5_test.bin \
--sysfw ti-sci-firmware-j721e-gp.bin \
--signing-key degenerateKey.pem \
--log-level DEBUG \
--output-file tiboot3.bin
```

### Sign SBL standalone

``` {.bash}
$ k3sign.py sbl-v1 --sbl dmsc_r5_test.bin \
--signing-key=degenerateKey.pem
```

### License

Please refer to LICENSE.md and manifest.html
