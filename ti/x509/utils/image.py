from ti.x509.macros import SHAType, ROMImageType, ROMBootCoreValue
from ti.x509.extensions import ImageComponentExtension, ROMImageIntegrityExtension, ROMBootSeqExtension
from ti.x509.utils.hash_wrapper import hash_binary


class Image():
    """Wrapper around basic image operations such as hashing and encryption"""

    inp_len = 0
    bin_hash = ""
    bin_len = 0
    hash_algo = SHAType.SHA2_512
    compType = ROMImageType.SBL
    cert_label = "sbl"
    load_addr = 0
    bootCore = ROMBootCoreValue.MCU
    boot_core_opts = 0

    def __init__(self, input_file,
                 hash_algo=SHAType.SHA2_512,
                 # Encryption Options
                 enc_key=None,
                 enc_out=None,
                 derive_key=False,
                 salt_file=None,
                 iv_file=None):

        self.hash_algo = hash_algo
        try:
            # Hash the binary with the specified algo
            with open(input_file, 'rb') as inp_fh:
                inp_bytes = inp_fh.read()
                self.inp_len = len(inp_bytes)
                self.bin_len = self.inp_len
                self.bin_hash = hash_binary(
                    inp_bytes, hash_algo=self.hash_algo)
        except:
            raise Exception("Unable to open file " + input_file)

    def get_image_comp_extension(self):
        """Returns an image component extension corresponding to the
        hashed and encrypted image"""

        ext = ImageComponentExtension()
        ext.shaValue = self.bin_hash
        ext.compSize = self.bin_len
        ext.shaType = self.hash_algo
        ext.compType = self.compType
        ext.cert_label = self.cert_label
        ext.bootCore = self.bootCore
        ext.destAddr = self.load_addr

        return ext

    def get_rom_image_integrity_extension(self):
        ext = ROMImageIntegrityExtension()
        ext.shaValue = self.bin_hash
        ext.shaAlgo = self.hash_algo
        return ext

    def get_rom_boot_seq_extension(self):
        ext = ROMBootSeqExtension()
        ext.compType = self.compType
        ext.boot_core = self.bootCore
        ext.boot_core_opts = self.boot_core_opts
        ext.destAddr = self.load_addr
        ext.imageSize = self.bin_len

        return ext

    def get_encryption_extension(self):
        pass

    def get_image_enc_extension(self):
        pass
