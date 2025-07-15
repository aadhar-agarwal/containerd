from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI
import sys
import json

def get_client():
    """Initialize and return the Azure OpenAI client"""
    token_provider = get_bearer_token_provider(
        DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
    )

    client = AzureOpenAI(
        api_version="2024-04-01-preview",
        azure_endpoint="https://aadagarwal-hack.openai.azure.com/",
        azure_ad_token_provider=token_provider
    )
    return client

def ask_gpt_for_test(func_name, file_code, primer):
    """Generate a test for the given function using GPT"""
    client = get_client()
    
    # Extract package name from the file code
    import re
    package_name = "main"  # Default
    if match := re.search(r'package\s+(\w+)', file_code):
        package_name = match.group(1)
    
    # Extract imports from the file code
    imports = []
    import_block_match = re.search(r'import\s+\(\s*(.*?)\s*\)', file_code, re.DOTALL)
    if import_block_match:
        import_block = import_block_match.group(1)
        for line in import_block.split('\n'):
            line = line.strip()
            if line and not line.startswith('//'):
                imports.append(line)
    
    prompt = f"""
Here is the full Go file content:
{file_code}

Please generate a test file for the function(s) named '{func_name}' in this file. Do not mock out any dependencies.
Please define the package name '{package_name}' and include the imports: {', '.join(imports)} in the test file

Very important: Wrap ALL code in ```go code blocks so it can be easily extracted.
Your response should provide exactly ONE complete, self-contained test function.
Do not include explanations outside the code blocks, put all comments inside the Go code."""
    response = client.chat.completions.create(
        model="gpt-4.1",  # model = "deployment_name"
        messages=[
            {"role": "system", "content": "You are a Go expert writing unit tests for containerd."},
            {"role": "user", "content": "Here is some relevant code and tests to understand before writing any tests:"},
            {"role": "user", "content": primer},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content

def main():
    """Main function to handle file input"""
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python gpt.py <input_file_path>"}))
        return 1
    
    input_file_path = sys.argv[1]
    
    try:
        # Read input data from file
        with open(input_file_path, 'r') as f:
            input_data = json.load(f)
        
        func_name = input_data.get('funcName', '')
        file_code = input_data.get('fileCode', '')
        primer = input_data.get('primer', '')
        # print(file_code)
        
        result = ask_gpt_for_test(func_name, file_code, primer)
        print(json.dumps({"result": result}))
        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1

# If the script is run directly, call main()
if __name__ == "__main__":
    sys.exit(main())