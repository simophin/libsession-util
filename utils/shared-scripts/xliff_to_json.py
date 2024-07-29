import os
import xml.etree.ElementTree as ET
import json
import sys
import argparse
import html

# Customizable mapping for output folder hierarchy
# Add entries here to customize the output path for specific locales
# Format: 'input_locale': 'output_path'
LOCALE_PATH_MAPPING = {
    'en-US': 'en',
    'es-419': 'es_419',
    'hy-AM': 'hy-AM',
    'kmr-TR': 'kmr',
    'pt-BR': 'pt_BR',
    'pt-PT': 'pt_PT',
    'zh-CN': 'zh_CN',
    'zh-TW': 'zh_TW'
    # Add more mappings as needed
}

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Convert an XLIFF file to JSON.')
parser.add_argument('input_file', help='File that should be converted')
parser.add_argument('output_directory', help='Directory to save the output files')
parser.add_argument('locale', help='Locale for the input file')
parser.add_argument('locale_two_letter_code', help='Two letter code for the locale')
args = parser.parse_args()

INPUT_FILE = args.input_file
OUTPUT_DIRECTORY = args.output_directory
LOCALE = args.locale
LOCALE_TWO_LETTER_CODE = args.locale_two_letter_code

def parse_xliff(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    namespace = {'ns': 'urn:oasis:names:tc:xliff:document:1.2'}
    translations = {}
    
    # Handle plural groups
    for group in root.findall('.//ns:group[@restype="x-gettext-plurals"]', namespaces=namespace):
        plural_forms = {}
        resname = None
        for trans_unit in group.findall('ns:trans-unit', namespaces=namespace):
            if resname is None:
                resname = trans_unit.get('resname')
            target = trans_unit.find('ns:target', namespaces=namespace)
            context_group = trans_unit.find('ns:context-group', namespaces=namespace)
            plural_form = context_group.find('ns:context[@context-type="x-plural-form"]', namespaces=namespace)
            if target is not None and target.text and plural_form is not None:
                form = plural_form.text.split(':')[-1].strip().lower()
                plural_forms[form] = target.text
        if resname and plural_forms:
            translations[resname] = plural_forms
    
    # Handle non-plural translations
    for trans_unit in root.findall('.//ns:trans-unit', namespaces=namespace):
        resname = trans_unit.get('resname')
        if resname not in translations:  # This is not part of a plural group
            target = trans_unit.find('ns:target', namespaces=namespace)
            if target is not None and target.text:
                translations[resname] = target.text
    
    return translations

def generate_icu_pattern(target):
    if isinstance(target, dict):  # It's a plural group
        pattern_parts = []
        for form, value in target.items():
            if form in ['zero', 'one', 'two', 'few', 'many', 'other', 'exact', 'fractional']:
                # Replace {count} with #
                value = html.unescape(value.replace('{count}', '#'))
                pattern_parts.append(f"{form} {{{value}}}")
        
        if 'other' not in target:
            pattern_parts.append("other {# other}")
        
        return "{{count, plural, {0}}}".format(" ".join(pattern_parts))
    else:  # It's a regular string
        return html.unescape(target)

def convert_xliff_to_json():
    # Determine the output path based on the mapping
    output_locale = LOCALE_PATH_MAPPING.get(LOCALE, LOCALE_PATH_MAPPING.get(LOCALE_TWO_LETTER_CODE, LOCALE_TWO_LETTER_CODE))
    locale_output_dir = os.path.join(OUTPUT_DIRECTORY, output_locale)
    os.makedirs(locale_output_dir, exist_ok=True)

    translations = parse_xliff(INPUT_FILE)
    output_file = os.path.join(locale_output_dir, 'messages.json')
    converted_translations = {}

    for resname, target in translations.items():
        converted_translations[resname] = generate_icu_pattern(target)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(converted_translations, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    try:
        convert_xliff_to_json()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Process interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)
