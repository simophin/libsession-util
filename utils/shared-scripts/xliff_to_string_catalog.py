import os
import xml.etree.ElementTree as ET
import json
import sys
import argparse
import re
from colorama import Fore, Style, init
import html

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Convert XLIFF files to Apple String Catalog.')
parser.add_argument('input_directory', help='Directory containing XLIFF files')
parser.add_argument('output_directory', help='Directory to save the output files')
args = parser.parse_args()

INPUT_DIRECTORY = args.input_directory
OUTPUT_DIRECTORY = args.output_directory

def parse_xliff(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    namespace = {'ns': 'urn:oasis:names:tc:xliff:document:1.2'}
    translations = {}
    
    file_elem = root.find('ns:file', namespaces=namespace)
    if file_elem is None:
        raise ValueError(f"Invalid XLIFF structure in file: {file_path}")

    target_language = file_elem.get('target-language')
    if target_language is None:
        raise ValueError(f"Missing target-language in file: {file_path}")
    
    for trans_unit in root.findall('.//ns:trans-unit', namespaces=namespace):
        resname = trans_unit.get('resname') or trans_unit.get('id')
        if resname is None:
            continue  # Skip entries without a resname or id
        
        target = trans_unit.find('ns:target', namespaces=namespace)
        source = trans_unit.find('ns:source', namespaces=namespace)
        
        if target is not None and target.text:
            translations[resname] = target.text
        elif source is not None and source.text:
            # If target is missing or empty, use source as a fallback
            translations[resname] = source.text
            print(f"Warning: Using source text for '{resname}' as target is missing or empty")

    # Handle plural groups
    for group in root.findall('.//ns:group[@restype="x-gettext-plurals"]', namespaces=namespace):
        plural_forms = {}
        resname = None
        for trans_unit in group.findall('ns:trans-unit', namespaces=namespace):
            if resname is None:
                resname = trans_unit.get('resname') or trans_unit.get('id')
            target = trans_unit.find('ns:target', namespaces=namespace)
            context_group = trans_unit.find('ns:context-group', namespaces=namespace)
            if context_group is not None:
                plural_form = context_group.find('ns:context[@context-type="x-plural-form"]', namespaces=namespace)
                if target is not None and target.text and plural_form is not None:
                    form = plural_form.text.split(':')[-1].strip().lower()
                    plural_forms[form] = target.text
        if resname and plural_forms:
            translations[resname] = plural_forms

    return translations, target_language

def convert_placeholders_for_plurals(resname, translations):
    # Replace {count} with %lld for iOS
    converted_translations = {}
    for form, value in translations.items():
        converted_translations[form] = html.unescape(value.replace('{count}', '%lld'))

    return converted_translations

def convert_xliff_to_string_catalog():
    string_catalog = {
        "sourceLanguage": "en",
        "strings": {},
        "version": "1.0"
    }

    for filename in os.listdir(INPUT_DIRECTORY):
        if filename.endswith('.xliff'):
            file_path = os.path.join(INPUT_DIRECTORY, filename)
            try:
                translations, target_language = parse_xliff(file_path)
            except Exception as e:
                print(f"Error processing file {filename}: {str(e)}")
                continue

            print(f"\033[2K{Fore.WHITE}⏳ Converting translations for {target_language} to target format...{Style.RESET_ALL}", end='\r')
            sorted_translations = sorted(translations.items())

            for resname, translation in sorted_translations:
                if resname not in string_catalog["strings"]:
                    string_catalog["strings"][resname] = {
                        "extractionState": "manual",
                        "localizations": {}
                    }

                if isinstance(translation, dict):  # It's a plural group
                    converted_translations = convert_placeholders_for_plurals(resname, translation)
                    
                    # Check if any of the translations contain '{count}'
                    contains_count = any('{count}' in value for value in translation.values())

                    if contains_count:
                        # It's a standard plural which the code can switch off of using `{count}`
                        variations = {
                            "plural": {
                                form: {
                                    "stringUnit": {
                                        "state": "translated",
                                        "value": value
                                    }
                                } for form, value in converted_translations.items()
                            }
                        }
                        string_catalog["strings"][resname]["localizations"][target_language] = {"variations": variations}
                    else:
                        # Otherwise we need to use a custom format which uses just the `{count}` and replaces it with an entire string
                        string_catalog["strings"][resname]["localizations"][target_language] = {
                            "stringUnit": {
                                "state": "translated",
                                "value": "%#@arg1@"
                            },
                            "substitutions": {
                                "arg1": {
                                    "argNum": 1,
                                    "formatSpecifier": "lld",
                                    "variations": {
                                        "plural": {
                                            form: {
                                                "stringUnit": {
                                                    "state": "translated",
                                                    "value": value
                                                }
                                            } for form, value in converted_translations.items()
                                        }
                                    }
                                }
                            }
                        }
                else:
                    string_catalog["strings"][resname]["localizations"][target_language] = {
                        "stringUnit": {
                            "state": "translated",
                            "value": html.unescape(translation)  # Just unescape, don't convert placeholders
                        }
                    }

    output_file = os.path.join(OUTPUT_DIRECTORY, 'Localizable.xcstrings')
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(string_catalog, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    try:
        convert_xliff_to_string_catalog()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Process interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)
