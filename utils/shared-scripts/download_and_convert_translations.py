import os
import requests
import json
import time
import sys
import argparse
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Download and convert Crowdin translations.')
parser.add_argument('api_token', help='Crowdin API token')
parser.add_argument('project_id', help='Crowdin project ID')
parser.add_argument('download_directory', help='Directory to save the initial downloaded files')
parser.add_argument('output_directory', help='Directory to save the output files')
parser.add_argument('conversion_script', help='Script to convert XLIFF to JSON')
parser.add_argument('--single-output', action='store_true', help='Conversion script generates a single output file')
parser.add_argument('--skip-untranslated-strings', action='store_true', help='Exclude strings which have not been translated from the translation files')
parser.add_argument('--force-allow-unapproved', action='store_true', help='Include unapproved translations in the translation files')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
args = parser.parse_args()

CROWDIN_API_BASE_URL = "https://api.crowdin.com/api/v2"
CROWDIN_API_TOKEN = args.api_token
CROWDIN_PROJECT_ID = args.project_id
DOWNLOAD_DIRECTORY = args.download_directory
OUTPUT_DIRECTORY = args.output_directory
CONVERSION_SCRIPT = args.conversion_script
SINGLE_OUTPUT = args.single_output
SKIP_UNTRANSLATED_STRINGS = args.skip_untranslated_strings
FORCE_ALLOW_UNAPPROVED = args.force_allow_unapproved
VERBOSE = args.verbose

# Function to check for errors in API responses
def check_error(response):
    if response.status_code != 200:
        print(f"\033[2K{Fore.RED}❌ Error: {response.json().get('error', {}).get('message', 'Unknown error')} (Code: {response.status_code}){Style.RESET_ALL}")
        if VERBOSE:
            print(f"{Fore.BLUE}Response: {json.dumps(response.json(), indent=2)}{Style.RESET_ALL}")
        sys.exit(1)

# Function to download a file from Crowdin
def download_file(url, output_path):
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with open(output_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

# Main function to handle the logic
def main():
    # Retrieve the list of languages
    print(f"{Fore.WHITE}⏳ Retrieving project details...{Style.RESET_ALL}", end='\r')
    project_response = requests.get(f"{CROWDIN_API_BASE_URL}/projects/{CROWDIN_PROJECT_ID}", 
                                      headers={"Authorization": f"Bearer {CROWDIN_API_TOKEN}"})
    check_error(project_response)
    project_details = project_response.json()['data']
    source_language_id = project_details['sourceLanguageId']
    target_languages = project_details['targetLanguages']
    num_languages = len(target_languages)
    print(f"\033[2K{Fore.GREEN}✅ Project details retrieved, found {num_languages} languages{Style.RESET_ALL}")

    if VERBOSE:
        print(f"{Fore.BLUE}Response: {json.dumps(project_response.json(), indent=2)}{Style.RESET_ALL}")

    # Ensure the download and output directories exist
    if not os.path.exists(DOWNLOAD_DIRECTORY):
        os.makedirs(DOWNLOAD_DIRECTORY)

    if not os.path.exists(OUTPUT_DIRECTORY):
        os.makedirs(OUTPUT_DIRECTORY)

    # Sort languages alphabetically by locale
    target_languages.sort(key=lambda x: x['locale'])

    # Iterate over each language and download the translations
    for index, language in enumerate(target_languages, start=1):
        lang_id = language['id']
        lang_locale = language['locale']
        prefix = f"({index:02d}/{num_languages:02d})"
        
        # Request export of translations for the specific language
        print(f"\033[2K{Fore.WHITE}⏳ {prefix} Exporting translations for {lang_locale}...{Style.RESET_ALL}", end='\r')
        export_payload = {
            "targetLanguageId": lang_id,
            "format": "xliff",
            "skipUntranslatedStrings": (True if SKIP_UNTRANSLATED_STRINGS and lang_id != source_language_id else False),
            "exportApprovedOnly": (False if FORCE_ALLOW_UNAPPROVED else True)
        }
        export_response = requests.post(f"{CROWDIN_API_BASE_URL}/projects/{CROWDIN_PROJECT_ID}/translations/exports",
                                        headers={"Authorization": f"Bearer {CROWDIN_API_TOKEN}", "Content-Type": "application/json"},
                                        data=json.dumps(export_payload))
        check_error(export_response)

        if VERBOSE:
            print(f"\n{Fore.BLUE}Response: {json.dumps(export_response.json(), indent=2)}{Style.RESET_ALL}")

        # Download the exported file
        download_url = export_response.json()['data']['url']
        download_path = os.path.join(DOWNLOAD_DIRECTORY, f"{lang_locale}.xliff")
        print(f"\033[2K{Fore.WHITE}⏳ {prefix} Downloading translations for {lang_locale}...{Style.RESET_ALL}", end='\r')
        try:
            download_file(download_url, download_path)
        except requests.exceptions.HTTPError as e:
            print(f"\033[2K{Fore.RED}❌ {prefix} Failed to download translations for {lang_locale} (Error: {e}){Style.RESET_ALL}")
            if VERBOSE:
                print(f"{Fore.BLUE}Response: {e.response.text}{Style.RESET_ALL}")
            sys.exit(1)

    # Completed downloading
    print(f"\033[2K{Fore.GREEN}✅ Downloading {num_languages} translations complete{Style.RESET_ALL}")

    # Convert translations
    if SINGLE_OUTPUT:
        print(f"\033[2K{Fore.WHITE}⏳ Converting all translations to target format...{Style.RESET_ALL}", end='\r')
        os.system(f"python3 {CONVERSION_SCRIPT} {DOWNLOAD_DIRECTORY} {OUTPUT_DIRECTORY}")
    else:
        for language in target_languages:
            lang_locale = language['locale']
            print(f"\033[2K{Fore.WHITE}⏳ Converting translations for {lang_locale} to target format...{Style.RESET_ALL}", end='\r')
            input_file = os.path.join(DOWNLOAD_DIRECTORY, f"{lang_locale}.xliff")
            os.system(f"python3 {CONVERSION_SCRIPT} {input_file} {OUTPUT_DIRECTORY} {lang_locale}")
    
    print(f"\033[2K{Fore.GREEN}✅ All conversions complete{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Process interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
