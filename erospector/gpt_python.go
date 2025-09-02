package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Response represents the JSON response from the Python script
type Response struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

// AskGPTForTestPython calls the Python script to generate a test using Azure OpenAI
func AskGPTForTestPython(fileCode string, primer string) (string, error) {
	// Get the path to the Python script
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	scriptPath := filepath.Join(dir, "gpt.py")

	// Check if the script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return "", errors.New("Python script not found at: " + scriptPath)
	}

	// Create a temporary file for the input data
	inputFile, err := os.CreateTemp("", "erospector-input-*.json")
	if err != nil {
		return "", errors.New("Error creating temporary file: " + err.Error())
	}
	defer os.Remove(inputFile.Name())

	// Write the input data as JSON
	inputData := map[string]string{
		"fileCode": fileCode,
		"primer":   primer,
	}

	inputJSON, err := json.Marshal(inputData)
	if err != nil {
		return "", errors.New("Error marshaling input data: " + err.Error())
	}
	if _, err := inputFile.Write(inputJSON); err != nil {
		return "", errors.New("Error writing to temporary file: " + err.Error())
	}
	if err := inputFile.Close(); err != nil {
		return "", errors.New("Error closing temporary file: " + err.Error())
	}

	// Run the Python script with the input file path as argument
	cmd := exec.Command("python3", scriptPath, inputFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return "", errors.New("Error executing Python script: " + err.Error())
	}

	// Parse the JSON response
	var response Response
	if err := json.Unmarshal(output, &response); err != nil {
		return "", errors.New("Error parsing Python output: " + err.Error())
	}

	// Check if there was an error in the Python script
	if response.Error != "" {
		return "", errors.New("Python error: " + response.Error)
	}

	return response.Result, nil
}

// Create a function that calls ask_gpt_for_test_and_run in gpt.py
func AskGPTForTestAndRun(fileCode string, testFileCode string) (string, error) {
	// Get the path to the Python script
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	scriptPath := filepath.Join(dir, "gpt.py")

	// Check if the script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return "", errors.New("Python script not found at: " + scriptPath)
	}

	// Create a temporary file for the input data
	inputFile, err := os.CreateTemp("", "erospector-input-*.json")
	if err != nil {
		return "", errors.New("Error creating temporary file: " + err.Error())
	}
	defer os.Remove(inputFile.Name())

	// Write the input data as JSON
	inputData := map[string]string{
		"fileCode":     fileCode,
		"testFileCode": testFileCode,
	}

	inputJSON, err := json.Marshal(inputData)
	if err != nil {
		return "", errors.New("Error marshaling input data: " + err.Error())
	}
	if _, err := inputFile.Write(inputJSON); err != nil {
		return "", errors.New("Error writing to temporary file: " + err.Error())
	}
	if err := inputFile.Close(); err != nil {
		return "", errors.New("Error closing temporary file: " + err.Error())
	}

	// Run the Python script with the input file path as argument
	cmd := exec.Command("python3", scriptPath, inputFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return "", errors.New("Error executing Python script: " + err.Error())
	}

	// Parse the JSON response
	var response Response
	if err := json.Unmarshal(output, &response); err != nil {
		return "", errors.New("Error parsing Python output: " + err.Error())
	}

	// Check if there was an error in the Python script
	if response.Error != "" {
		return "", errors.New("Python error: " + response.Error)
	}

	return response.Result, nil
}

// AskGPTForTestPythonWithMode calls the Python script with a specified mode
func AskGPTForTestPythonWithMode(fileCode string, primer string, mode string, sourceFilePath string) (string, error) {
	// Get the path to the Python script
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	scriptPath := filepath.Join(dir, "gpt.py")

	// Check if the script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return "", errors.New("Python script not found at: " + scriptPath)
	}

	// Create a temporary file for the input data
	inputFile, err := os.CreateTemp("", "erospector-input-*.json")
	if err != nil {
		return "", errors.New("Error creating temporary file: " + err.Error())
	}
	defer os.Remove(inputFile.Name())

	// Write the input data as JSON
	inputData := map[string]string{
		"fileCode":       fileCode,
		"primer":         primer,
		"mode":           mode,
		"sourceFilePath": sourceFilePath,
	}
	inputJSON, err := json.Marshal(inputData)
	if err != nil {
		return "", errors.New("Error marshaling input data: " + err.Error())
	}
	if _, err := inputFile.Write(inputJSON); err != nil {
		return "", errors.New("Error writing to temporary file: " + err.Error())
	}
	if err := inputFile.Close(); err != nil {
		return "", errors.New("Error closing temporary file: " + err.Error())
	}

	// Run the Python script with the input file path as argument
	cmd := exec.Command("python3", scriptPath, inputFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return "", errors.New("Error executing Python script: " + err.Error())
	}

	// Parse the JSON response
	var response Response
	if err := json.Unmarshal(output, &response); err != nil {
		return "", errors.New("Error parsing Python output: " + err.Error())
	}

	// Check if there was an error in the Python script
	if response.Error != "" {
		return "", errors.New("Python error: " + response.Error)
	}

	return response.Result, nil
}
