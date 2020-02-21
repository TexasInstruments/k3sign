import logging
from textwrap import dedent
from ti.x509.macros import ROMImageType, SHAType, ROMBootCoreValue


class TIX509Extension:
    description = "TI X509 Extension Base class"
    cert_label = "ti_x509_base"
    oid = "1.2.3.4.5.6"

    def __str__(self):
        logging.error("Print function not implemented")

    def get_toc_entry(self):
        return "{0}=ASN1:SEQUENCE:{1}".format(self.oid, self.cert_label)


class ROMX509Extension(TIX509Extension):
    description = "TI X509 Extension Base class - ROM Specific"
    cert_label = "rom_x509_base"


class SYSFWX509Extension(TIX509Extension):
    description = "TI X509 Extension Base class - SYSFW Specific"
    cert_label = "sysfw_x509_base"


class SWRevExtension(ROMX509Extension):
    swrev = 0
    description = " SW Revision Extension for roll back protection"
    cert_label = "swrv"
    oid = "1.3.6.1.4.1.294.1.3"

    def __init__(self, rev=0):
        self.swrev = rev

    def __str__(self):
        template = "[{0}]\nswrv=INTEGER:{1}\n"
        out_str = template.format(self.cert_label, self.swrev)
        return out_str

    def get_toc_entry(self):
        return "{0}=ASN1:SEQUENCE:{1}".format(self.oid, self.cert_label)

# TODO: Needs implementation


class ExtendedEncInfoExtension(ROMX509Extension):
    def get_toc_entry(self):
        return "test"


class ExtendedEncInfoTOCExtension(ROMX509Extension):
    oid = "1.3.6.1.4.1.294.1.10"
    cert_label = "ext_enc_info"
    enc_components = []

    def __init__(self, *args):
        if len(args) == 0:
            raise Exception("No encryption Information available")
        for ext in args:
            if isinstance(ext, ExtendedEncInfoExtension):
                self.enc_components.append(ext)
            else:
                raise TypeError(
                    "Invalid object passed for encryption information")

    def __str__(self):
        template = "[{0}]\nnumComp = INTEGER:{1}\n"
        out_str = template.format(self.cert_label, len(self.enc_components))
        for ext in self.enc_components:
            out_str = out_str + "\n" + ext.get_toc_entry()

        return out_str


class ROMDebugExtension(ROMX509Extension):
    pass


class ROMEncryptionExtension(ROMX509Extension):
    """Encryption extension supported by
    - ROM
    - System Firmware
    """
    pass


class ImageComponentExtension(ROMX509Extension):
    compType = ROMImageType.SBL
    bootCore = 0
    compOpts = 0
    destAddr = 0
    compSize = 0
    shaType = SHAType.SHA2_512
    shaValue = 0
    cert_label = "comp1"

    def __str__(self):
        template = """\
        [{0}]
        compType = INTEGER:{1}
        bootCore = INTEGER:{2}
        compOpts = INTEGER:{3}
        destAddr = FORMAT:HEX,OCT:{4:08x}
        compSize = INTEGER:{5}
        shaType  = OID:{6}
        shaValue = FORMAT:HEX,OCT:{7}
        """
        out_str = template.format(self.cert_label,
                                  self.compType.cert_entry,
                                  self.bootCore.value, self.compOpts, self.destAddr,
                                  self.compSize, self.shaType.oid, self.shaValue)

        return dedent(out_str)

    def get_toc_entry(self):
        out_str = "{0}=SEQUENCE:{1}".format(
            self.compType.text_val, self.cert_label)
        return out_str


class ExtendedBootInfo(ROMX509Extension):

    image_components = []
    cert_label = "ext_boot_info"
    oid = "1.3.6.1.4.1.294.1.9"

    def __init__(self, *args):
        if len(args) == 0:
            raise Exception("No Boot component information available")
        for ext in args:
            if isinstance(ext, ImageComponentExtension):
                self.image_components.append(ext)
            else:
                raise TypeError(
                    "Invalid object passed for image component information")

    def append(self, ext):
        """Add a Image component to Extended Boot Info"""
        if isinstance(ext, ImageComponentExtension):
            self.image_components.append(ext)
        else:
            raise TypeError(
                "Invalid object passed for image component information")

    def __str__(self):
        template = """\
        [{0}]
        extImgSize=INTEGER:{1}
        numComp=INTEGER:{2}"""

        img_size = sum(list(map(lambda x: x.compSize, self.image_components)))
        out_str = template.format(self.cert_label,
                                  img_size,
                                  len(self.image_components))
        out_str = dedent(out_str)
        comp_str = ""
        for ext in self.image_components:
            out_str = out_str + "\n" + ext.get_toc_entry()
            comp_str = comp_str + "\n" + str(ext)

        out_str = out_str + "\n" + comp_str
        return out_str

    def get_toc_entry(self):
        return "{0}=ASN1:SEQUENCE:{1}".format(self.oid, self.cert_label)


class ROMBootSeqExtension(ROMX509Extension):

    oid = "1.3.6.1.4.1.294.1.1"
    cert_label = "boot_seq"
    compType = ROMImageType.SBL
    boot_core = ROMBootCoreValue.MCU
    boot_core_opts = 0
    destAddr = 0
    imageSize = 0

    def __str__(self):
        template = """\
            [{0}]
            certType     =  INTEGER:{1}
            bootCore     =  INTEGER:{2}
            bootCoreOpts =  INTEGER:{3}
            destAddr     =  FORMAT:HEX,OCT:{4:08x}
            imageSize    =  INTEGER:{5}
            """
        out_str = template.format(self.cert_label, self.compType.cert_entry,
                                  self.boot_core.value, self.boot_core_opts,
                                  self.destAddr, self.imageSize)
        return dedent(out_str)


class ROMImageIntegrityExtension(ROMX509Extension):

    shaValue = ""
    shaType = SHAType.SHA2_512
    oid = "1.3.6.1.4.1.294.1.2"
    cert_label = "image_integrity"

    def __str__(self):
        template = """\
        [{0}]
        shaType=OID:{1}
        shaValue=FORMAT:HEX,OCT:{2}
        """

        out_str = template.format(
            self.cert_label, self.shaType.oid, self.shaValue)
        return dedent(out_str)


SYSFW_SUPPORTED_EXTS = [SWRevExtension, ROMEncryptionExtension]

ROM_V1_SUPPORTED_EXTS = [SWRevExtension,
                         ROMEncryptionExtension, ROMDebugExtension,
                         ROMBootSeqExtension, ROMImageIntegrityExtension]

ROM_V2_SUPPORTED_EXTS = [SWRevExtension, ROMDebugExtension,
                         ImageComponentExtension, ExtendedBootInfo,
                         ExtendedEncInfoExtension, ExtendedEncInfoTOCExtension]

if __name__ == "__main__":
    a = ImageComponentExtension()
    print(a)
    print(a.get_toc_entry())
