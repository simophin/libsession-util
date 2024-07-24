import os
import xml.etree.ElementTree as ET
import json
import sys
import argparse
import re
from colorama import Fore, Style, init

# Variables that should be treated as numeric (using %lld)
NUMERIC_VARIABLES = ['count', 'total_count']

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

def get_source_text(file_path, resname):
    tree = ET.parse(file_path)
    root = tree.getroot()
    namespace = {'ns': 'urn:oasis:names:tc:xliff:document:1.2'}
    
    for trans_unit in root.findall('.//ns:trans-unit', namespaces=namespace):
        if (trans_unit.get('resname') or trans_unit.get('id')) == resname:
            source = trans_unit.find('ns:source', namespaces=namespace)
            if source is not None and source.text:
                return source.text
    return ""  # Return empty string if source not found

def unescape_ampersand(text):
    return text.replace('&amp;', '&')

def convert_placeholders(resname, source_text, target_text):
    source_vars = re.findall(r'\{([^}]+)\}', source_text)
    var_indices = {}
    for idx, var in enumerate(source_vars):
        if var not in var_indices:
            var_indices[var] = []
        var_indices[var].append(idx + 1)

    def repl(match):
        var_name = match.group(1)
        if var_name in var_indices:
            if len(var_indices[var_name]) > 0:
                index = var_indices[var_name].pop(0)
                if var_name in NUMERIC_VARIABLES:
                    return f"%{index}$lld"
                else:
                    return f"%{index}$@"
            else:
                print(f"Warning: Variable '{var_name}' appears more times in target than in source for '{resname}'")
                return match.group(0)  # Keep unchanged if we've run out of indices
        return match.group(0)  # Keep unchanged if not found in source

    result = re.sub(r'\{([^}]+)\}', repl, target_text)

    # Check if any variables weren't used
    for var, indices in var_indices.items():
        if indices:
            print(f"Warning: Variable '{var}' appears {len(indices)} more time(s) in source than in target for '{resname}'")
    
    return unescape_ampersand(result)

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

            for resname, translation in translations.items():
                if resname not in string_catalog["strings"]:
                    string_catalog["strings"][resname] = {
                        "extractionState": "manual",
                        "localizations": {}
                    }

                source_text = get_source_text(file_path, resname)

                if isinstance(translation, dict):  # It's a plural group
                    variations = {
                        "plural": {
                            form: {
                                "stringUnit": {
                                    "state": "translated",
                                    "value": convert_placeholders(resname, source_text, value)
                                }
                            } for form, value in translation.items()
                        }
                    }
                    string_catalog["strings"][resname]["localizations"][target_language] = {"variations": variations}
                else:
                    string_catalog["strings"][resname]["localizations"][target_language] = {
                        "stringUnit": {
                            "state": "translated",
                            "value": convert_placeholders(resname, source_text, translation)
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
