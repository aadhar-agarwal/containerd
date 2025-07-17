from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI
import sys
import json
import subprocess
import re
import os
import tempfile
import shutil

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


def run_go_tests_with_code(source_file_code: str, test_file_code: str, source_file_path: str = None) -> dict:
    """Run Go tests with source code strings, using actual file paths when available"""
    if source_file_path:
        # Use the actual file location for better context
        source_dir = os.path.dirname(source_file_path)
        source_filename = os.path.basename(source_file_path)
        
        # Generate test file name by replacing .go with _test.go
        if source_filename.endswith('.go'):
            test_filename = source_filename[:-3] + '_test.go'
        else:
            test_filename = source_filename + '_test.go'
        
        test_file_path = os.path.join(source_dir, test_filename)
        
        # Write the test file in the same directory as the source
        try:
            with open(test_file_path, 'w') as f:
                f.write(test_file_code)
            
            # Run tests in the source directory
            result = subprocess.run(
                ["go", "test", "-coverprofile=cover.out", "./..."],
                cwd=source_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            # Parse coverage % from go tool output
            try:
                cov = subprocess.run(
                    ["go", "tool", "cover", "-func=cover.out"],
                    cwd=source_dir,
                    capture_output=True,
                    text=True,
                )
                match = re.search(r"total:\s+\(statements\)\s+([\d.]+)%", cov.stdout)
                coverage = float(match.group(1)) if match else 0.0
            except Exception:
                coverage = 0.0
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "coverage_percent": coverage,
                "returncode": result.returncode,
                "test_file_path": test_file_path
            }
            
        except Exception as e:
            return {"error": f"Failed to write test file or run tests: {str(e)}"}
    else:
        # Fallback to temporary directory method
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write the source code to files
            source_path = os.path.join(temp_dir, "source.go")
            test_path = os.path.join(temp_dir, "source_test.go")
            
            with open(source_path, 'w') as f:
                f.write(source_file_code)
            
            with open(test_path, 'w') as f:
                f.write(test_file_code)

            try:
                result = subprocess.run(
                    ["go", "test", "-coverprofile=cover.out"],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except Exception as e:
                return {"error": str(e)}

            # Parse coverage % from go tool output
            try:
                cov = subprocess.run(
                    ["go", "tool", "cover", "-func=cover.out"],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                )
                match = re.search(r"total:\s+\(statements\)\s+([\d.]+)%", cov.stdout)
                coverage = float(match.group(1)) if match else 0.0
            except Exception:
                coverage = 0.0

            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "coverage_percent": coverage,
                "returncode": result.returncode
            }

def ask_gpt_for_test(file_code, primer):
    """Generate a test for the whole file using GPT"""
    client = get_client()

    prompt = f"""
Here is the full Go file content:
{file_code}

Please generate unit tests for the entire file.
Do not mock out any dependencies.
Please simplify the tests as much as possible.
"""
    response = client.chat.completions.create(
        model="gpt-4.1",  # model = "deployment_name"
        messages=[
            {"role": "system", "content": "You are a Go expert writing unit tests for containerd."},
            {"role": "user", "content": "Here is some relevant code and tests to understand before writing any tests:"},
            {"role": "user", "content": primer},
            {"role": "user", "content": prompt}
        ],
        # input=[{"role": "user", "content": "Once the test is generated, run the go tests, and fix any issues until the tests run."}],
        # tools=tools
    )
    return response.choices[0].message.content

def ask_gpt_for_test_and_run(file_code, primer, source_file_path=None):
    """Generate a test for the whole file using GPT with iterative testing"""
    client = get_client()

    tools = [{
        "type": "function",
        "function": {
            "name": "run_go_tests_with_code",
            "description": "Run Go tests and return the results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_file_code": {
                        "type": "string",
                        "description": "Code of the Go source file."
                    },
                    "test_file_code": {
                        "type": "string",
                        "description": "Code of the Go test file."
                    },
                    "source_file_path": {
                        "type": "string",
                        "description": "Path to the Go source file for testing in proper context."
                    }
                },
                "required": [
                    "source_file_code",
                    "test_file_code",
                    "source_file_path"
                ],
                "additionalProperties": False
            }
        }
    }]

    prompt = f"""
Here is the full Go file content:
{file_code}

Please generate unit tests for the entire file.
Do not mock out any dependencies.
Please simplify the tests as much as possible.

IMPORTANT: After generating the test code, you MUST use the run_go_tests_with_code function to test it immediately. 
Call the function with the original source code, your generated test code, and the source file path: {source_file_path}
If there are any errors, fix them and run the tests again until they pass.
Do not ask for permission - just run the tests automatically.
"""
    
    messages = [
        {"role": "system", "content": "You are a Go expert writing unit tests for containerd. You MUST run tests automatically using the run_go_tests_with_code function after generating test code. Do not ask for permission. In addition, fix any issues until the tests run successfully"},
        {"role": "user", "content": "Here is some relevant code and tests to understand before writing any tests:"},
        {"role": "user", "content": primer},
        {"role": "user", "content": prompt}
    ]
    
    response = client.chat.completions.create(
        model="gpt-4.1",
        messages=messages,
        tools=tools
    )
    
    # Handle function calls if the model wants to use tools
    if response.choices[0].message.tool_calls:
        # Add the assistant's response to messages
        messages.append(response.choices[0].message)
        
        # Process each tool call
        for tool_call in response.choices[0].message.tool_calls:
            if tool_call.function.name == "run_go_tests_with_code":
                # Parse the function arguments
                args = json.loads(tool_call.function.arguments)
                
                # Execute the function with code strings and source file path
                result = run_go_tests_with_code(
                    args["source_file_code"], 
                    args["test_file_code"],
                    args.get("source_file_path", source_file_path)
                )

                # Add the function result to messages
                messages.append({
                    "role": "tool",
                    "content": json.dumps(result),
                    "tool_call_id": tool_call.id
                })
        
        # Get the final response after function execution
        final_response = client.chat.completions.create(
            model="gpt-4.1",
            messages=messages + [{
                "role": "user",
                "content": "Please provide the final, corrected test code as a complete Go test file. Do not describe what you did - just provide the working code."
            }],
            tools=tools
        )
        
        return final_response.choices[0].message.content
    # else:
    #     # No function calls were made, let's force a test run
    #     # Extract the test code from the response and run it
    #     test_code = response.choices[0].message.content
        
    #     # Try to run the tests with the generated code
    #     try:
    #         result = run_go_tests_with_code(file_code, test_code, source_file_path)
            
    #         # Add the result to the conversation and ask the model to improve if needed
    #         messages.append(response.choices[0].message)
    #         messages.append({
    #             "role": "user", 
    #             "content": f"I ran your test code and got these results:\n{json.dumps(result, indent=2)}\n\nPlease analyze the results and provide the final, corrected test code as a complete Go test file. If there were errors, fix them. Do not describe what you're doing - just provide the working code."
    #         })
            
    #         final_response = client.chat.completions.create(
    #             model="gpt-4.1",
    #             messages=messages
    #         )
            
    #         return final_response.choices[0].message.content
    #     except Exception as e:
    #         # If we can't run the tests, just return the original response
    #         return test_code


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

        file_code = input_data.get('fileCode', '')
        primer = input_data.get('primer', '')
        mode = input_data.get('mode', 'simple')  # 'simple' or 'test_and_run'
        source_file_path = input_data.get('sourceFilePath', '')
        
        if mode == 'test_and_run':
            result = ask_gpt_for_test_and_run(file_code, primer, source_file_path)
        else:
            result = ask_gpt_for_test(file_code, primer)
            
        print(json.dumps({"result": result}))
        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1

# If the script is run directly, call main()
if __name__ == "__main__":
    sys.exit(main())