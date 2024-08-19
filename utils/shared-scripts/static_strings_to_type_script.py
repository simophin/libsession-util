import json
import sys
import argparse
from pathlib import Path

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Convert static strings data to a TypeScript file.')
parser.add_argument('static_string_json', help='Static string data')
parser.add_argument('output_path', help='Path to save the static string file')
args = parser.parse_args()

STATIC_STRING_JSON = args.static_string_json
OUTPUT_PATH = args.output_path

# Main function to handle the logic
def main():
    Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    entries = json.loads(STATIC_STRING_JSON)['data']

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write('export enum LOCALE_DEFAULTS {\n')
        for entry in entries:
            key = entry['data']['note']
            text = entry['data']['text']
            f.write(f"  {key} = '{text}',\n")

        f.write('}\n')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Process interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
