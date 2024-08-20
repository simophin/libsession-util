import os
import xml.etree.ElementTree as ET
import sys
import argparse
import re

# Variables that should be treated as numeric (using %d)
NUMERIC_VARIABLES = ['count', 'found_count', 'total_count']

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Convert an XLIFF file to Android XML.')
parser.add_argument('input_file', help='File that should be converted')
parser.add_argument('output_directory', help='Directory to save the output files')
parser.add_argument('locale', help='Locale for the input file')
parser.add_argument('locale_two_letter_code', help='Two letter code for the locale')
parser.add_argument('--default_locale', help='Default locale (will use "values" folder)', default='en-US')
args = parser.parse_args()

INPUT_FILE = args.input_file
OUTPUT_DIRECTORY = args.output_directory
LOCALE = args.locale
DEFAULT_LOCALE = args.default_locale

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

def convert_placeholders(text):
    def repl(match):
        var_name = match.group(1)
        index = len(set(re.findall(r'\{([^}]+)\}', text[:match.start()]))) + 1
        
        if var_name in NUMERIC_VARIABLES:
            return f"%{index}$d"
        else:
            return f"%{index}$s"

    return re.sub(r'\{([^}]+)\}', repl, text)

def escape_android_string(text):
    # We can use standard XML escaped characters for most things (since XLIFF is an XML format) but
    # want the following cases escaped in a particulat way
    text = text.replace("'", r"\'")
    text = text.replace("&quot;", "\"")
    text = text.replace("\"", "\\\"")
    text = text.replace("&lt;b&gt;", "<b>")
    text = text.replace("&lt;/b&gt;", "</b>")
    text = text.replace("&lt;/br&gt;", "\n")
    text = text.replace("<br/>", "\n")
    return text

def write_android_xml(translations, output_file):
    sorted_translations = sorted(translations.items())

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n')
        f.write('<resources>\n')
        for resname, target in sorted_translations:
            if isinstance(target, dict):  # It's a plural group
                f.write(f'    <plurals name="{resname}">\n')
                for form, value in target.items():
                    escaped_value = escape_android_string(convert_placeholders(value))
                    f.write(f'        <item quantity="{form}">{escaped_value}</item>\n')
                f.write('    </plurals>\n')
            else:  # It's a regular string (for these we DON'T want to convert the placeholders)
                escaped_target = escape_android_string(target)
                f.write(f'    <string name="{resname}">{escaped_target}</string>\n')
        f.write('</resources>')

def convert_xliff_to_android_xml():
    translations = parse_xliff(INPUT_FILE)

    # Generate output paths
    language_code = LOCALE.split('-')[0]
    region_code = LOCALE.split('-')[1] if '-' in LOCALE else None

    if LOCALE == DEFAULT_LOCALE:
        language_output_dir = os.path.join(OUTPUT_DIRECTORY, 'values')
    else:
        language_output_dir = os.path.join(OUTPUT_DIRECTORY, f'values-{language_code}')

    os.makedirs(language_output_dir, exist_ok=True)
    language_output_file = os.path.join(language_output_dir, 'strings.xml')
    write_android_xml(translations, language_output_file)

    if region_code:
        region_output_dir = os.path.join(OUTPUT_DIRECTORY, f'values-{language_code}-r{region_code}')
        os.makedirs(region_output_dir, exist_ok=True)
        region_output_file = os.path.join(region_output_dir, 'strings.xml')
        write_android_xml(translations, region_output_file)

if __name__ == "__main__":
    try:
        convert_xliff_to_android_xml()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)
