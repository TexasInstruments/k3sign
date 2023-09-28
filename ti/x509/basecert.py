"""Base class for both ROM and SYSFW Certificates"""
import os
import logging
import subprocess
from tempfile import mkstemp
from ti.x509.macros import SHAType, SigAlgos

X509_BOILER_PLATE = """\
[ req ]
distinguished_name     = req_distinguished_name
x509_extensions        = v3_ca
prompt                 = no

dirstring_type = nobmp

[ req_distinguished_name ]
C                      = US
ST                     = SC
L                      = Dallas
O                      = Texas Instruments., Inc.
OU                     = PBU
CN                     = Albert
emailAddress           = Albert@ti.com

[ v3_ca ]
basicConstraints = CA:true"""


class BaseX509Cert():

    def sign(self, output_file, key_file=None, keep_intermediate_files=False,
             sha_type=SHAType.SHA2_512, sig_algo= SigAlgos.RSA_PKCS_SHA512):
        """Sign an X509 Certificate"""

        if key_file is None:
            raise Exception("Key file invalid")

        (cert_temp_open_handle, cert_temp_fname) = mkstemp(suffix='.txt',
                                                           prefix='x509_template_',
                                                           text=True)
        cert_temp_fh = os.fdopen(cert_temp_open_handle, mode="wt")
        logging.debug("Created file for X509 template %s", cert_temp_fname)
        logging.debug("filehandle for X509 template %s", type(cert_temp_fh))
        logging.debug("filehandle for X509 template %s", cert_temp_fh)
        cert_temp_fh.write(str(self))
        cert_temp_fh.close()

        # Sign the certificate
        signing_args = [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            key_file,
            "-nodes",
            "-outform",
            "DER",
            "-out",
            output_file,
            "-config",
            cert_temp_fname,
            "-" + sha_type.openssl_arg
        ]

        # Add additional parameters when PSS signing algorithm is detected
        # Currently, the PSS related parameters are hardcoded,
        # we may accept the values through parameters.
        if sig_algo.algo_str == "rsassapss":
            signing_args += [
                    "-sigopt",
                    "rsa_padding_mode:pss",
                    "-sigopt",
                    "rsa_pss_saltlen:64",
                    "-sigopt",
                    "rsa_mgf1_md:" + sha_type.openssl_arg,
            ]

        logging.debug("OpenSSL command used is %s", ' '.join(signing_args))

        subprocess.run(signing_args, check=True)

        if keep_intermediate_files:
            logging.info("Leaving intermediate files in %s", cert_temp_fname)
        else:
            logging.debug("Deleting temporary file %s", cert_temp_fname)
            os.remove(cert_temp_fname)
