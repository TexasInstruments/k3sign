"""This module defines various enums that are used in the signing process in one place"""
from enum import Enum


class ROMImageType(Enum):
    """Defines image types supported by ROM

    This is referred to as Certificate Type in the context of Version 1 ROM
    certificate and component type in the context of Version 2 ROM certificate

    """
    SBL = (1, "sbl")
    SYSFW = (2, "sysfw")
    SYSFW_INNER_CERT = (3, "sysfw_inner_cert")
    SBL_DATA_SECTION = (17, "sbl_data_section")
    SYSFW_DATA_SECTION = (18, "sysfw_data_section")

    def __init__(self, cert_entry, text_val):
        self.cert_entry = cert_entry
        self.text_val = text_val


class SHAType(Enum):
    """
    Enums for SHA algorithm used in hash calculation

    Only including SHA2 512 for now.
    """
    SHA2_512 = ("2.16.840.1.101.3.4.2.3", "sha512", 64)

    def __init__(self, oid, openssl_arg, sha_len_bytes):
        self.oid = oid
        self.openssl_arg = openssl_arg
        self.sha_len_bytes = sha_len_bytes


class ROMCertVersion(Enum):
    """
    Enums identifying different versions of ROM certificates

    Version 1 is supported on all devices.
    Version 2 is unsupported on AM65x (PG1 and PG2), J721E (PG1)
    """
    ROM_CERT_VER_1 = 1
    ROM_CERT_VER_2 = 2


class ROMBootCoreValue(Enum):
    """
    Enums identifying the core that a certificate or component belongs to

    Applicable to version 1 certificates
    """
    DMSC = 0
    DMSC_CERT = 8
    MCU = 16
    RESERVED = 32

# With python 3.5/3.6, one can use Flag and IntFlag instead of enum


class ROMCoreOption(Enum):
    """
    Defines the boot options for MCU running SBL.
    """
    THUMB_MODE = 1
    SPLIT_MODE = 2

class SigAlgos(Enum):
    """
    Enums for Signature algorithm.

    """
    RSA_PKCS_SHA512 = ("1.2.840.113549.1.1.13", "sha512wrsa")
    RSA_PKCS_SHA384 = ("1.2.840.113549.1.1.12", "sha384wrsa")
    RSA_PKCS_SHA256 = ("1.2.840.113549.1.1.11", "sha256wrsa")
    RSASSA_PSS = ("1.2.840.113549.1.1.10", "rsassapss")

    def __init__(self, oid, algo_str):
        self.oid = oid
        self.algo_str = algo_str
