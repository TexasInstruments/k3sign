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

### Getting help

``k3sign.py`` has multiple subcommands to handle different usecases.
Run the below command to get a list of subcommands.

``` {.bash}
$ k3sign.py --help
usage: k3sign.py [-h] {sbl-v2,sysfw-inner,sysfw-outer,sbl-v1} ...

positional arguments:
  {sbl-v2,sysfw-inner,sysfw-outer,sbl-v1}
                        sub-command help

optional arguments:
  -h, --help            show this help message and exit

```

Invoke subcommands with ``-h`` or ``--help`` argument to get detailed help.

``` {.bash}
$ ./k3sign.py sbl-v2 --help
usage: k3sign.py sbl-v2 [-h] [--sbl SBL] [--sbl-load-addr SBL_LOAD_ADDR]
                        [--device-type DEVICE_TYPE] [--sw-rev SW_REV]
                        [--log-level {INFO,DEBUG}] [--output-file OUTPUT_FILE]
                        [--sysfw SYSFW] [--sysfw-load-addr SYSFW_LOAD_ADDR]
                        [--sysfw-signing-key SYSFW_SIGNING_KEY]
                        [--sysfw-cert-out SYSFW_CERT_OUT]
                        [--sysfw-data SYSFW_DATA]
                        [--sysfw-data-load-addr SYSFW_DATA_LOAD_ADDR]
                        --signing-key SIGNING_KEY [--cert-out CERT_OUT]
```


### Sign SBL and SYSFW for the combined image format

``` {.bash}
$ k3sign.py sbl-v2 --sbl dmsc_r5_test.bin \
--sysfw ti-sci-firmware-j721e-gp.bin \
--signing-key degenerateKey.pem \
--log-level DEBUG \
--output-file tiboot3.bin
```
### Sign SBL, SYSFW and board configuration for the combined image format

``` {.bash}
$ k3sign.py sbl-v2 --sbl dmsc_r5_test.bin \
--sysfw ti-sci-firmware-j7200-gp.bin \
--signing-key degenerateKey.pem \
--sysfw-data boardcfg-combined.bin \
--sysfw-data-load-addr 0x7A000 \
--log-level DEBUG \
--output-file tiboot3.bin
```

- Board configuration blob must contain all four board configurations
  (baseport, rm, pm and security) with the required table of contents.
  
- ``sysfw-data-load-addr`` specifies the load location of board configuration.
  User must ensure that load location of board configuration does not overlap
  with System Firmware binary.
  

### Sign SBL standalone

``` {.bash}
$ k3sign.py sbl-v1 --sbl dmsc_r5_test.bin \
--signing-key=degenerateKey.pem
```

### License

Please refer to LICENSE.md and manifest.html
