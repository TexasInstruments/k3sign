"""This module defines a class for the ROM X509 certificate structure"""
from ti.x509.macros import ROMCertVersion
from ti.x509.extensions import SWRevExtension, ExtendedBootInfo, \
    ExtendedEncInfoTOCExtension, \
    ROMDebugExtension, ROMImageIntegrityExtension, ROM_V1_SUPPORTED_EXTS, ROM_V2_SUPPORTED_EXTS
from ti.x509.basecert import BaseX509Cert, X509_BOILER_PLATE

# ROM Cert must have atleast SW Rev and the following combinations
# a. ext_boot_info [ext_enc_info] For the new combined image format
# (or)
# b. boot_seq, image_integrity, [encryption], [ sysfw_hs_boardcfg ]
#
# In both cases, debug extension is optional


class ROMX509Cert(BaseX509Cert):
    """Class defining the ROM X509 certificate"""

    # Default to version 1
    cert_ver = ROMCertVersion.ROM_CERT_VER_1

    # Initialize to empty list
    exts = []

    def _init_cert_ver_1(self, args):
        for ext in args:
            if any(list(map(lambda x: isinstance(ext, x), ROM_V1_SUPPORTED_EXTS))):
                self.exts.append(ext)
            else:
                raise TypeError(ext)

    def _init_cert_ver_2(self, args):
        for ext in args:
            if any(list(map(lambda x: isinstance(ext, x), ROM_V2_SUPPORTED_EXTS))):
                self.exts.append(ext)
            else:
                raise TypeError(ext)

    def __init__(self, cert_ver, sw_rev_ext, *args):
        """
        cert_ver - enum indicating type of certificate

        sw_rev_ext - SW Revision Extension

        args - various extensions that need to be included
        in the certificate
        """

        if not isinstance(cert_ver, ROMCertVersion):
            raise TypeError("unexpected cert version")

        if not isinstance(sw_rev_ext, SWRevExtension):
            raise TypeError("SW Revision extension expected")

        self.exts.append(sw_rev_ext)

        if cert_ver == ROMCertVersion.ROM_CERT_VER_1:
            self._init_cert_ver_1(args)
        elif cert_ver == ROMCertVersion.ROM_CERT_VER_2:
            self._init_cert_ver_2(args)
        else:
            raise Exception("Unhandled certificate version")

    def __str__(self):
        out_str = X509_BOILER_PLATE
        comp_str = ""
        for ext in self.exts:
            try:
                comp_str = comp_str + "\n" + str(ext)
            except:
                raise Exception("__str__ not implemented")
            try:
                out_str = out_str + "\n" + ext.get_toc_entry()
            except:
                print(ext)
                raise Exception("get_toc_entry not implemented")

        out_str = out_str + "\n" + comp_str
        return out_str
