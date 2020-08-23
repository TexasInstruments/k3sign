#!/usr/bin/env python3
import argparse
import logging
from tempfile import mkstemp
from ti.x509.extensions import ExtendedBootInfo, SWRevExtension
from ti.x509.macros import ROMImageType, ROMCertVersion, ROMBootCoreValue
from ti.x509.utils.hash_wrapper import hash_binary_into_ImageCompExtension
from ti.x509.romcert import ROMX509Cert
from ti.x509.utils.concat import concat_file
from ti.x509.utils.image import Image


def hex_addr(x):
    """Simple validator for load addresses"""
    return int(x, 16)


def sbl_sign_v2(args):
    """Sign SBL in the combined image format

    """
    if args.sbl is None or args.sysfw is None:
        logging.error(
            "Both SBL and SYSFW are needed for combined image format")
        raise Exception("Insufficient arguments")

    if args.sysfw_data is None:
        logging.warning(
            "ROM allows a combined image containing just SBL and SYSFW")
        logging.warning(
            "SYSFW expects the SYSFW Data section to be present in combined image")

    logging.info("Reading SBL from %s", args.sbl.name)
    logging.info("Reading SYSFW from %s", args.sysfw.name)

    if args.sysfw_data is not None:
        logging.info("Reading SYSFW data section from %s",
                     args.sysfw_data.name)

    sbl_image = Image(args.sbl.name)
    sbl_image.load_addr = args.sbl_load_addr
    sbl_image.compType = ROMImageType.SBL
    sbl_image.bootCore = ROMBootCoreValue.MCU
    sbl_image.cert_label = "sbl"

    sbl_img_comp_ext = sbl_image.get_image_comp_extension()

    sysfw_img = Image(args.sysfw.name)
    sysfw_img.load_addr = args.sysfw_load_addr
    sysfw_img.compType = ROMImageType.SYSFW
    sysfw_img.bootCore = ROMBootCoreValue.DMSC
    sysfw_img.cert_label = "sysfw"

    sysfw_img_comp_ext = sysfw_img.get_image_comp_extension()

    combined_boot_info_ext = ExtendedBootInfo(
        sbl_img_comp_ext, sysfw_img_comp_ext)

    if args.sysfw_data is not None:
        sysfw_data_img = Image(args.sysfw_data.name)
        sysfw_data_img.load_addr = args.sysfw_data_load_addr
        sysfw_data_img.compType = ROMImageType.SYSFW_DATA_SECTION
        sysfw_data_img.bootCore = ROMBootCoreValue.DMSC
        sysfw_data_img.cert_label = "sysfw_data"

        sysfw_data_img_comp_ext = sysfw_data_img.get_image_comp_extension()
        combined_boot_info_ext.append(sysfw_data_img_comp_ext)

    # logging.error(combined_boot_info_ext)
    # logging.error(combined_boot_info_ext.get_toc_entry())

    sw_rev = SWRevExtension(args.sw_rev)

    rom_cert = ROMX509Cert(ROMCertVersion.ROM_CERT_VER_2,
                           sw_rev, combined_boot_info_ext)

    logging.debug("ROM Certificate Template\n%s\n", rom_cert)

    if args.cert_out is None:
        (cert_handle, cert_fname) = mkstemp(suffix='.bin',
                                            prefix='x509_cert_',
                                            text=False)
    else:
        cert_fname = args.cert_out.name

    rom_cert.sign(cert_fname,
                  key_file=args.signing_key.name,
                  keep_intermediate_files=True)

    files_to_concat = [cert_fname, args.sbl.name, args.sysfw.name]

    if args.sysfw_data is not None:
        files_to_concat.append(args.sysfw_data.name)

    concat_file(args.output_file.name, files_to_concat)


def common_sign_v1(args):

    logging.info("Reading INP from %s", args.inp.name)
    inp_bytes = args.inp.read()

    inp_image = Image(args.inp.name)
    inp_image.load_addr = args.inp_load_addr
    inp_image.compType = args.compType
    inp_image.bootCore = args.bootCore

    sw_rev = SWRevExtension(args.sw_rev)
    rom_image_integ_ext = inp_image.get_rom_image_integrity_extension()
    rom_boot_seq_ext = inp_image.get_rom_boot_seq_extension()

    rom_cert = ROMX509Cert(ROMCertVersion.ROM_CERT_VER_1,
                           sw_rev, rom_image_integ_ext, rom_boot_seq_ext)

    logging.debug("ROM Certificate Template\n%s", rom_cert)

    if args.cert_out is None:
        (cert_handle, cert_fname) = mkstemp(suffix='.bin',
                                            prefix='x509_cert_',
                                            text=False)
    else:
        cert_fname = args.cert_out.name

    rom_cert.sign(cert_fname, args.signing_key.name)

    # TODO: This will change when using encryption
    if args.output_file is not None:
        concat_file(args.output_file.name,
                    [cert_fname, args.inp.name])

    return


def sbl_sign_v1(args):

    logging.info("Reading SBL from %s", args.sbl.name)

    common_args = object()
    common_args.inp = sbl
    common_args.inp_load_addr = args.sbl_load_addr
    common_args.compType = ROMImageType.SBL
    common_args.bootCore = ROMBootCoreValue.MCU
    common_args.sw_rev = args.swrev
    common_args.cert_out = args.cert_out
    common_args.signing_key = args.signing_key
    common_args.output_file = args.output_file

    common_sign_v1(common_args)

    return


def sysfw_sign_inner(args):

    logging.info("Reading SYSFW from %s", args.sysfw.name)

    common_args = object()
    common_args.inp = args.sysfw
    common_args.inp_load_addr = args.sysfw_load_addr
    common_args.compType = ROMImageType.SYSFW
    common_args.bootCore = ROMBootCoreValue.MCU
    common_args.sw_rev = args.swrev
    common_args.cert_out = args.cert_out
    common_args.signing_key = args.signing_key
    common_args.output_file = args.output_file

    common_sign_v1(common_args)

    return


def sysfw_sign_outer(args):

    logging.info("Reading SYSFW from %s", args.sysfw.name)

    common_args = object()
    common_args.inp = args.sysfw
    common_args.inp_load_addr = args.sysfw_load_addr
    common_args.compType = ROMImageType.SYSFW
    common_args.bootCore = ROMBootCoreValue.MCU
    common_args.sw_rev = args.swrev
    common_args.cert_out = args.cert_out
    common_args.signing_key = args.signing_key
    common_args.output_file = args.output_file

    common_sign_v1(common_args)

    return

# sbl common options -> sbl load address, output file, sbl binary, sbl options, debug option
# v1-sbl
# v1-sysfw-outer
# v1-sysfw-inner, v2-sysfw-inner
# v2-sbl
# sysfw-app
# sysfw-in-place
# sysfw-debug
# v1-sign-board-configuration


# parent parser for common sbl signing options
sbl_pp = argparse.ArgumentParser(add_help=False)
sbl_pp.add_argument('--sbl', type=argparse.FileType('rb'))
sbl_pp.add_argument('--sbl-load-addr', type=hex_addr, default=0x41c00000)

# parent parser for encryption options
enc_pp = argparse.ArgumentParser(add_help=False)
enc_group = enc_pp.add_argument_group(title="Encryption Options (Not Supported Yet)",
                                      description="Options for encrypting binary on HS devices")
enc_group.add_argument('--enc-key', type=argparse.FileType('rb'))
enc_group.add_argument('--enc-out', type=argparse.FileType('wb'))

# Parent parser for signing options
sign_pp = argparse.ArgumentParser(add_help=False)
sign_group = sign_pp.add_argument_group(title="Signing Options",
                                        description="Options for Signing")
sign_group.add_argument(
    '--signing-key', type=argparse.FileType('rb'), required=True)
sign_group.add_argument('--cert-out', type=argparse.FileType('wb'))

# Common Options for parser
common_pp = argparse.ArgumentParser(add_help=False)
common_pp.add_argument('--device-type')
common_pp.add_argument('--sw-rev', type=int, default=0)
common_pp.add_argument('--log-level', type=str,
                       default="INFO", choices=["INFO", "DEBUG"])
common_pp.add_argument('--output-file', type=argparse.FileType('wb'))

# TODO: Add argument to force SBL to combined image format
sysfw_pp = argparse.ArgumentParser(add_help=False)
sysfw_pp.add_argument('--sysfw', type=argparse.FileType('rb'))
sysfw_pp.add_argument('--sysfw-load-addr', type=hex_addr, default=0x40000)
sysfw_pp.add_argument('--sysfw-signing-key', type=argparse.FileType('rb'))
sysfw_pp.add_argument('--sysfw-cert-out', type=argparse.FileType('wb'))
sysfw_pp.add_argument('--sysfw-data', type=argparse.FileType('rb'))
sysfw_pp.add_argument('--sysfw-data-load-addr', type=hex_addr, default=0x7F000)

parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
subparsers = parser.add_subparsers(
    help='sub-command help', dest='subparser_name')
parser_sbl_sign_v2 = subparsers.add_parser(
    'sbl-v2', parents=[sbl_pp, common_pp, sysfw_pp, sign_pp])
parser_sbl_sign_v2.set_defaults(func=sbl_sign_v2)

parser_sysfw_inner_sign = subparsers.add_parser(
    'sysfw-inner', parents=[common_pp, sysfw_pp, enc_pp])
parser_sysfw_inner_sign.set_defaults(func=sysfw_sign_inner)

parser_sysfw_outer_sign = subparsers.add_parser(
    'sysfw-outer', parents=[common_pp])
parser_sysfw_outer_sign.set_defaults(func=sysfw_sign_outer)

# parser.add_argument('--sysfw-inner-cert', type=argparse.FileType('rb'))
parser_sbl_sign_v1 = subparsers.add_parser('sbl-v1', parents=[sbl_pp, common_pp,
                                                              enc_pp, sign_pp])
parser_sbl_sign_v1.set_defaults(func=sbl_sign_v1)

args = parser.parse_args()

# All the subcommands have a default log level argument
# If log_level argument is not set, set log level to DEBUG
if hasattr(args, "log_level"):
    logging.getLogger().setLevel(args.log_level)
else:
    logging.getLogger().setLevel("DEBUG")

logging.debug(args)

# Invoke function corresponding to the invoked sub command
if hasattr(args, "func"):
    args.func(args)
else:
    parser.print_help()
