# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os
import sys
import textwrap
from collections import ChainMap

from lib4sbom.parser import SBOMParser

import sbom2doc.generator as generator
import sbom2doc.simple_format_generator as simple_generator
from sbom2doc.version import VERSION

# CLI processing

def parse_additional_license_texts(additional_license_texts_file):
    additional_license_texts = None
    try:
        with open(os.path.abspath(additional_license_texts_file)) as f:
            additional_license_texts = json.load(f)
        assert type(additional_license_texts) is dict, "Did not find a JSON object"

        additional_license_texts_caps = {}
        for k in additional_license_texts:
            additional_license_texts_caps[k.upper()] = additional_license_texts[k]
        return additional_license_texts_caps
    except Exception as e:
        raise Exception(f"Expected path to JSON file with object, got '{additional_license_texts_file}'") from e

def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbom2doc"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOM2doc generates documentation for a SBOM.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="Name of SBOM file",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )

    output_group.add_argument(
        "--include-license",
        action="store_true",
        default=False,
        help="add license text",
    )

    output_group.add_argument(
        "--additional-license-texts",
        action="store",
        default=None,
        help="Provide a JSON file with an object {LICENSE_ID: 'LICENSE TEXT'} to add license texts for generation.",
    )

    # Add format option
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        help="Output format (default: output to console)",
        choices=["console", "json", "markdown", "pdf"],
        default="console",
    )

    output_group.add_argument(
        "-s",
        "--content-structure",
        action="store",
        default="full",
        help="content structure [simple | full] (default: full)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "output_file": "",
        "debug": False,
        "cotent_structure": "full",
        "format": "console",
        "include_license": False,
        "additional_license_texts": None,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] SBOM name must be specified.")
        return -1

    if args["format"] != "console" and args["output_file"] == "":
        print("[ERROR] Output filename must be specified.")
        return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Output file", args["output_file"])
        print("Include license text", args["include_license"])

    if args["content_structure"] not in ["full", "simple"]:
        print("[Error] Unrecognized content structure, use [full | simple].")

    sbom_parser = SBOMParser()
    # Load SBOM - will autodetect SBOM type
    try:
        sbom_parser.parse_file(input_file)
        additional_license_texts=None
        if args["additional_license_texts"] is not None:
            additional_license_texts = parse_additional_license_texts(args["additional_license_texts"])

        g = generator
        if args["content_structure"] == "simple":
            g = simple_generator

        g.generate_document(
            args["format"],
            sbom_parser,
            input_file,
            args["output_file"],
            args["include_license"],
            debug=args["debug"],
            additional_license_texts=additional_license_texts
        )

    except FileNotFoundError:
        print(f"{input_file} not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
