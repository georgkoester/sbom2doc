# Copyright (C) 2023 sbom2doc contributors
# SPDX-License-Identifier: Apache-2.0

import requests
import os
import datetime
from lib4sbom.data.document import SBOMDocument
from lib4sbom.license import LicenseScanner

from sbom2doc.docbuilder.consolebuilder import ConsoleBuilder
from sbom2doc.docbuilder.jsonbuilder import JSONBuilder
from sbom2doc.docbuilder.markdownbuilder import MarkdownBuilder
from sbom2doc.docbuilder.pdfbuilder import PDFBuilder

license_syns = {
    "Apache-2.0": [
        "https://www.apache.org/licenses/LICENSE-2.0;description=Apache-2.0",
        "https://www.apache.org/licenses/LICENSE-2.0.txt",
        "http://www.apache.org/licenses/LICENSE-2.0.txt",
        "https://www.apache.org/licenses/LICENSE-2.0.html",
        "https://www.apache.org/licenses/LICENSE-2.0",
        "http://www.apache.org/licenses/LICENSE-2.0.html;"
        "description=Apache 2.0 License",
        "Apache-2.0 license",
        '"Apache License 2.0";link="http://www.apache.org/licenses/LICENSE-2.0.html"',
    ],
    "BSD-3-Clause": [
        "https://opensource.org/licenses/BSD-3-Clause",
        "3-Clause BSD License",
        "http://www.eclipse.org/org/documents/edl-v10.php",
        "BSD 3-Clause",
        "BSD 3-Clause License",
    ],
    "BSD-2-Clause": [
        "https://opensource.org/licenses/BSD-2-Clause",
        "https://opensource.org/licenses/BSD-2-Clause;description=BSD 2-Clause License",
    ],
    "CDDL-1.1": [
        "https://github.com/javaee/activation/blob/master/LICENSE.txt",
    ],
    "ZPL-2.1": [
        "ZPL 2.1",
    ],
    "MIT" : [
        "http://www.opensource.org/licenses/mit-license.php",
    ],
}
license_syns_reverse = {}
for k, v in license_syns.items():
    for kk in v:
        license_syns_reverse[kk] = k


copyright_info_missing_package_name_list = {}
unknown_license_text_id_list = {}
license_info_missing_package_id_list = {}

def _ensure_len(text, max_len):
    if max_len < 3:
        raise Exception("At least 3 min length! Better 10...")
    if text is not None:
        text = str(text)
        if len(text) > max_len:
            text = f"{text[:(max_len - 3)]}..."
    return text


def _get_licenses(o):
    possible_additional_info = None
    package_name = o.get("name", "(package name missing)")

    license_list = o.get("licenselist", None)
    if license_list is not None and len(license_list) > 0:
        license_list_simple = []
        for l in license_list:
            if not "license" in l:
                continue
            if "id" in l["license"]:
                license_list_simple.append(l["license"]["id"])
            elif "name" in l["license"]:
                license_list_simple.append(l["license"]["name"])
                continue
            elif "text" in l["license"]:
                license_list_simple.append(l["license"]["text"])
                continue
        if len(license_list_simple) > 0:
            return license_list_simple

    license = o.get("licenseconcluded", "NOT KNOWN")
    if license == "NOT KNOWN":
        print(f"Missing license: '{package_name}': '{o}'")
        license_info_missing_package_id_list[package_name] = True
    return [license]

def _get_copyright(o):
    name = o.get("name", "(package name missing)")
    failed_text = f"Not extracted, please search {name}"
    result = o.get("copyrighttext", failed_text)
    if failed_text == result:
        copyright_info_missing_package_name_list[name] = True
    return result

def generate_document(
    format, sbom_parser, filename, outfile, include_license, debug=False, additional_license_texts=None
):
    # Get constituent components of the SBOM
    packages = sbom_parser.get_packages()
    files = sbom_parser.get_files()
    relationships = sbom_parser.get_relationships()
    document = SBOMDocument()
    document.copy_document(sbom_parser.get_document())
    license_info = LicenseScanner()

    def _find_license_id(value):
        """
        Uses the LicenseScanner and own synonyms.
        Returns value if nothing found.
        """
        if value in license_syns_reverse:
            return license_syns_reverse[value]
        found = license_info.find_license_id(value)
        if found != license_info.DEFAULT_LICENSE:
            return found
        return value

    # Select document builder based on format
    if format == "markdown":
        sbom_document = MarkdownBuilder()
    elif format == "json":
        sbom_document = JSONBuilder()
    elif format == "pdf":
        sbom_document = PDFBuilder()
    else:
        sbom_document = ConsoleBuilder()

    sbom_document.heading(1, "SBOM Summary")

    # creator_identified = False
    # creator = document.get_creator()
    # # If creator is missing, will return None
    # if creator is not None:
    #     for c in creator:
    #         creator_identified = True
    #         sbom_document.addrow(["Creator", f"{c[0]}:{c[1]}"])

    sbom_document.paragraph(
        f"""SBOM File: {os.path.split(filename)[1]}
SBOM Type: {document.get_type()}
Version: {document.get_version()}
Name: {document.get_name()}
Created: {document.get_created()}
Files: {str(len(files))}
Packages: {str(len(packages))}
Relationships: {str(len(relationships))}"""
    )

    files_valid = True
    packages_valid = True
    relationships_valid = len(relationships) > 0
    sbom_licenses = []
    sbom_components = []
    sbom_suppliers = []

    for package in packages:
        licenses = _get_licenses(package)
        sbom_licenses.extend(licenses)
    for f in files:
        licenses = _get_licenses(f)
        sbom_licenses.extend(licenses)

    freq = {}
    for items in sorted(sbom_licenses):
        freq[items] = sbom_licenses.count(items)

    if debug:
        freq_sorted = [(f, license) for license, f in freq.items()]
        freq_sorted = sorted(freq_sorted, key=lambda x: x[0], reverse=True)
        print("License information:")
        for f, licenses in freq_sorted:
            print(f"{f} times: {_ensure_len(licenses, 200)} END")

    licenses_by_id = {}
    for k in freq.keys():
        if k is None or k == "NOT KNOWN":
            continue
        k = str(k)
        license_text = None
        if len(k) > 200 and "\n" in k:
            # just assume that it is the license_text at this length with newlines
            license_text = k

        elif license_info.license_expression(k):
            print(f"WARNING: License expression found, not fully supported: {k}")

        resolved = _find_license_id(k)
        if resolved != k:
            if debug:
                print(f"Resolved {_ensure_len(k, 20)} with {resolved}")
            k = resolved

        if k in licenses_by_id:
            existing_text = licenses_by_id[k]["license_text"]
            if license_text is not None and existing_text is not None:
                if license_text != existing_text:
                    if debug:
                        print(
                            "Conflict between two different versions "
                            f"for license id {k}! "
                            f"ONE {license_text}\nTWO: {existing_text} END"
                        )
                    else:
                        print(
                            "Conflict between two different versions for "
                            f"license id {k}! Check with debug."
                        )

            if existing_text is not None:
                license_text = existing_text

        licenses_by_id[k] = {"id": k, "license_text": license_text}

    if include_license:
        for key, value in licenses_by_id.items():
            # Ignore undefined licenses or expressions
            if key == "NOASSERTION":
                continue
            if value["license_text"] is not None:
                continue  # has text already
            if len(key) > 200:
                if debug:
                    print(
                        "Ignore long license key when getting texts, "
                        f"length: {len(key)}"
                    )
                continue
            if license_info.license_expression(key):
                if debug:
                    print(f"Ignore license expression when getting text: {key}")
                continue

            key_stripped = key.strip()
            if " " in key_stripped:
                if debug:
                    print(
                        "Ignore license id with space when "
                        f"querying spdx text: {key_stripped}"
                    )
                continue

            if key_stripped.startswith("http"):
                # assume URL, ignore
                continue

            license_url = f"https://spdx.org/licenses/{key_stripped}.json"
            license_done = False
            try:
                license_text = requests.get(license_url).json()
                if license_text.get("licenseText") is not None:
                    value["license_text"] = license_text.get("licenseText")
                    license_done = True
            except requests.exceptions.RequestException:
                print(f"No license text found in SPDX db for {key_stripped}: RequestException")

            if not license_done:
                if additional_license_texts is not None and key_stripped.upper() in additional_license_texts:
                        value["license_text"] = additional_license_texts[key_stripped.upper()]
                else:
                    print(f"No license text found for {key_stripped}")

    if len(packages) > 0:

        sbom_document.heading(1, "Package information")
        # sbom_document.createtable(
        #    ["Name", "Version", "Type", "Supplier", "License"], [12, 8, 8, 8, 12]
        # )
        for package in packages:
            # Minimum elements are ID, Name, Version, Supplier
            id = package.get("id", None)
            name = package.get("name", None)
            version = package.get("version", None)
            type = package.get("type", None)
            supplier = package.get("supplier", None)
            licenses = _get_licenses(package)
            licenses = [_find_license_id(l) for l in licenses]
            licenses_multiline = '\n'.join(licenses)

            sbom_components.append(type)
            if supplier is not None:
                sbom_suppliers.append(supplier)

            sbom_document.heading(2, f"Package: {id}")
            sbom_document.paragraph(
                f"""ID: {id}
Name: {name}
Version: {version}
Type: {type}
License id(s) or text: {licenses_multiline}
"""
            )
            copyright = _get_copyright(package)
            if copyright is not None and copyright != "NOT KNOWN":
                sbom_document.paragraph(f"Copyright:")
                sbom_document.paragraph(copyright, style=sbom_document.small_body)

            if (
                id is None
                or name is None
                or version is None
                or supplier is None
                or supplier == "NOASSERTION"
            ):
                packages_valid = False

    if include_license:
        sbom_document.heading(1, "License texts")

        licenses = list(licenses_by_id.values())
        licenses = sorted(licenses, key=lambda d: d["id"])
        for l in licenses:
            if l["id"] in ["UNKNOWN", "NOASSERTION", ""]:
                continue
            limited_length_id = _ensure_len(l["id"], 50)
            sbom_document.heading(2, limited_length_id)
            sbom_document.paragraph("License:")
            paragraph_text = f"No license text for id {l['id']}"
            if "license_text" in l:
                license_text = l["license_text"]
                if license_text is not None:
                    paragraph_text = license_text
                else:
                    unknown_license_text_id_list[l['id']] = True

            sbom_document.paragraph(paragraph_text, style=sbom_document.small_body)

    sbom_document.heading(1, "Component Type Summary")
    sbom_document.createtable(["Type", "Count"], [20, 10])
    #
    # Create an empty dictionary
    freq = {}
    for items in sorted(sbom_components):
        freq[items] = sbom_components.count(items)
    freq_sorted = [(f, comp) for comp, f in freq.items()]
    freq_sorted = sorted(freq_sorted, key=lambda x: x[0], reverse=True)
    for key, value in freq_sorted:
        sbom_document.addrow([str(value), str(key)])
    sbom_document.showtable(widths=[10, 3])

    # sbom_document.heading(1, "NTIA Summary")
    # sbom_document.createtable(["Element", "Status"])
    # sbom_document.addrow(["All file information provided?", str(files_valid)])
    # sbom_document.addrow(["All package information provided?", str(packages_valid)])
    # sbom_document.addrow(
    #     ["Dependency relationships provided?", str(relationships_valid)]
    # )
    # sbom_document.showtable(widths=[10, 4])

    # valid_sbom = (
    #     files_valid
    #     and packages_valid
    #     and relationships_valid
    # )
    # sbom_document.paragraph(f"NTIA conformant {valid_sbom}")

    sbom_document.publish(outfile)

    if debug:
        timestamp = datetime.datetime.now().isoformat().replace(":", "")
        timestamp = timestamp[:timestamp.find(".")]
        if len(license_info_missing_package_id_list) > 0:
            lines = ['"package id","license id"' + os.linesep]
            lines.extend([f'"{k}",""{os.linesep}' for k in license_info_missing_package_id_list])

            missing_license_info_filename = f"packages_missing_license_info-{timestamp}.csv"
            print(f"Writing {missing_license_info_filename}")
            with open(missing_license_info_filename, "x", encoding='utf-8'  ) as missing_license_info_file:
                    missing_license_info_file.writelines(lines)

        if len(copyright_info_missing_package_name_list) > 0:
            lines = ['"package id","copyright info"' + os.linesep]
            lines.extend([f'"{k}",""{os.linesep}' for k in copyright_info_missing_package_name_list])

            missing_copyright_info_filename = f"packages_missing_copyright_info-{timestamp}.csv"
            print(f"Writing {missing_copyright_info_filename}")
            with open(missing_copyright_info_filename, "x", encoding='utf-8') as missing_copyright_info_file:
                    missing_copyright_info_file.writelines(lines)

        if len(unknown_license_text_id_list) > 0:
            lines = ['"license id","original id synonym","license text"' + os.linesep]
            lines.extend([f'"{k}","",""{os.linesep}' for k in unknown_license_text_id_list])

            unknown_license_text_filename = f"license_ids_missing_text-{timestamp}.csv"
            print(f"Writing {unknown_license_text_filename}")
            with open(unknown_license_text_filename, "x", encoding='utf-8') as unknown_license_text_file:
                    unknown_license_text_file.writelines(lines)
