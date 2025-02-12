import subprocess
import os
import tempfile
import json

def run_html_function(html_file, function_name, *args):
    """
    Runs a JavaScript function in an HTML file using Node.js and returns the result.
    Handles potential errors during the execution and provides detailed debugging information.
    """

    # Construct a JavaScript command that calls the specified function with arguments
    js_code = f"""
    const jsdom = require("jsdom");
    const {{ JSDOM }} = require("jsdom");
    const fs = require('fs');
    const html = fs.readFileSync('{html_file}', 'utf-8');
    const dom = new JSDOM(html);
    const window = dom.window;
    global.window = window;
    global.document = window.document;
    global.navigator = {{ userAgent: 'node.js' }}; // Mock navigator
    global.CryptoJS = require('crypto-js');

    try {{
        const result = window.{function_name}({', '.join(map(json_encode, args))});
        console.log(JSON.stringify({{result: result, error: null}}));
    }} catch (error) {{
        console.error(error); // Log the error for debugging
        console.log(JSON.stringify({{result: null, error: error.message}}));
    }}
    """

    # Create a temporary JavaScript file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as tmp_file:
        tmp_file.write(js_code)
        tmp_js_file = tmp_file.name

    # Execute the JavaScript file using Node.js
    try:
        result = subprocess.run(["node", tmp_js_file], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"Error executing JavaScript: {result.stderr}")
            return None, result.stderr

        # Parse the JSON output
        try:
            output = json.loads(result.stdout)
            return output['result'], output['error']  # Return result and error
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            print(f"Raw output: {result.stdout}")  # Print raw output for debugging
            return None, str(e)

    except subprocess.TimeoutExpired:
        print("JavaScript execution timed out.")
        return None, "TimeoutExpired"
    except FileNotFoundError:
        print("Node.js not found. Please ensure Node.js is installed and in your PATH.")
        return None, "Node.js not found"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None, str(e)
    finally:
        # Clean up the temporary JavaScript file
        os.remove(tmp_js_file)

def json_encode(data):
    """
    Encode data to JSON string suitable for JavaScript. Handles strings and None types.
    """
    if data is None:
        return 'null'
    if isinstance(data, str):
        # Escape special characters for JavaScript string
        escaped_string = data.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
        return f'"{escaped_string}"'  # Wrap in double quotes
    return str(data)  # Do not convert to lowercase string

def qa_test_encryption(html_encrypt_file, html_decrypt_file, test_cases):
    """
    QA tests the encryption and decryption functions in encrypt.html and decrypt.html.
    """

    print("Starting QA test...\n")
    total_tests = len(test_cases)
    passed_tests = 0
    failed_tests = 0

    try:
        with open("english.txt", "r") as f:
            bip39_wordlist = set(f.read().splitlines())
    except FileNotFoundError:
        print("Error: english.txt not found. Make sure it's in the same directory.")
        print("Seed phrase validation will be skipped.")
        bip39_wordlist = None  # Or an empty set: bip39_wordlist = set()

    for i, test_case in enumerate(test_cases):
        benefactor_key = test_case["benefactor_key"]
        beneficiary_key = test_case["beneficiary_key"]
        seed_phrase = test_case["seed_phrase"]

        print(f"Test Case {i+1}/{total_tests}:")
        print(f" - Benefactor Key: {benefactor_key}")
        print(f" - Beneficiary Key: {beneficiary_key}")
        print(f" - Seed Phrase: {seed_phrase}")

        # 1. Encryption
        encrypted_result, encrypt_error = run_html_function(
            html_encrypt_file,
            "encryptSeedPhrase",  # Changed function name
            benefactor_key,
            benefactor_key,  # confirm benefactor key
            beneficiary_key,
            beneficiary_key,  # confirm beneficiary key
            seed_phrase
        )

        if encrypt_error:
            print(f" - Encryption Failed: {encrypt_error}")
            failed_tests += 1
            print("\n")
            continue

        print(f" - Encrypted Seed Phrase: {encrypted_result[:50]}...")  # Print first 50 chars

        # 2. Decryption
        decrypted_result, decrypt_error = run_html_function(
            html_decrypt_file,
            "decryptSeedPhrase",
            benefactor_key,
            beneficiary_key,
            encrypted_result  # Pass the encrypted string
        )

        if decrypt_error:
            print(f" - Decryption Failed: {decrypt_error}")
            failed_tests += 1
            print("\n")
            continue

        decrypted_seed_phrase = decrypted_result

        print(f" - Decrypted Seed Phrase: {decrypted_seed_phrase}")

        # 3. Verification
        if decrypted_seed_phrase == seed_phrase:
            print(" - Test Passed!")
            passed_tests += 1
        else:
            print(" - Test Failed: Decrypted seed phrase does not match the original.")
            failed_tests += 1
            print(" - Expected:", seed_phrase)
            print(" - Got:", decrypted_seed_phrase)
            print("\n")

    print("\n--- Test Results ---")
    print(f"Total Tests: {total_tests}")
    print(f"Passed Tests: {passed_tests}")
    print(f"Failed Tests: {failed_tests}")

if __name__ == "__main__":
    import json

    # Define the paths to your encrypt.html and decrypt.html files
    html_encrypt_file = "encrypt3.html"
    html_decrypt_file = "decrypt3.html"  # Replace with the actual path

    # Check if the files exist
    if not os.path.exists(html_encrypt_file):
        print(f"Error: {html_encrypt_file} not found.")
        exit(1)
    if not os.path.exists(html_decrypt_file):
        print(f"Error: {html_decrypt_file} not found.")
        exit(1)
    if not os.path.exists("english.txt"):
        print("Warning: english.txt not found. Make sure it is in the same directory")

    # Define a list of test cases. These should be *carefully* crafted
    # to expose potential weaknesses. Include edge cases, long keys,
    # short keys, etc.
    # IMPORTANT: Because of the CryptoJS library, these keys can be
    # arbitrary strings, not just lowercase letters. Same for the
    # seed phrase! This is a major change from your original design.
    test_cases = [
        {
            "benefactor_key": "TestBenefactor123!",
            "beneficiary_key": "BeneficiaryTest456@",
            "seed_phrase": "abandon ability able about above absent absorb abstract absurd abuse access accident accomplish account accuse achieve acid acoustic acquire across act action actor actress actual adapt"
        },
        {
            "benefactor_key": "PureTextBenefactor",
            "beneficiary_key": "PureTextBeneficiary",
            "seed_phrase": "abandon ability able about above absent absorb abstract absurd abuse access accident accomplish account accuse achieve acid acoustic acquire across act action actor actress actual adapt"
        },
        {
            "benefactor_key": "MixedCase123",
            "beneficiary_key": "MixedCase456",
            "seed_phrase": "petroleum skill olympic direct defense universe metal chief gravity peanut discover segment"
        },
        {
            "benefactor_key": "SpecialChars!@#",
            "beneficiary_key": "MoreChars$%^",
            "seed_phrase": "petroleum skill olympic direct defense universe metal chief gravity peanut discover segment"
        },
        {
            "benefactor_key": "TestBenefactor123!",
            "beneficiary_key": "BeneficiaryTest456@",
            "seed_phrase": "wrong seed phrase"
        }
    ]

    qa_test_encryption(html_encrypt_file, html_decrypt_file, test_cases) # Call to qa_test_encryption
