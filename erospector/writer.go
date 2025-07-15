package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// extractGoCodeBlocks extracts code inside Go code blocks marked by ```go or ```golang
func extractGoCodeBlocks(content string) string {
	// Regular expression to match Go code blocks in markdown
	codeBlockRegex := regexp.MustCompile("(?s)```(?:go|golang)\\s*\n(.*?)```")

	// Find all matches
	matches := codeBlockRegex.FindAllStringSubmatch(content, -1)

	if len(matches) == 0 {
		// If no Go code blocks are found, try to find any code blocks
		codeBlockRegex = regexp.MustCompile("(?s)```\\s*\n(.*?)```")
		matches = codeBlockRegex.FindAllStringSubmatch(content, -1)
		if len(matches) == 0 {
			// If still no code blocks, return the original content
			return content
		}
	}

	// Concatenate all Go code blocks
	var result strings.Builder
	for _, match := range matches {
		if len(match) >= 2 {
			// Use the code exactly as it appears in the code block
			code := match[1]
			result.WriteString(code)
			result.WriteString("\n\n")
		}
	}

	return result.String()
}

func WriteTestFile(sourceFile string, testCode string) (string, error) {
	// Get the directory where the source file is located
	sourceDir := filepath.Dir(sourceFile)

	// Get the base filename without extension
	base := strings.TrimSuffix(filepath.Base(sourceFile), ".go")

	// Create the test file path in the same directory as the source file
	testFile := filepath.Join(sourceDir, base+"_test.go")

	// Extract Go code from the GPT response
	// goCode := extractGoCodeBlocks(testCode)

	// Check if the file exists
	fileExists := false
	_, err := os.Stat(testFile)
	if err == nil {
		fileExists = true
	}

	var f *os.File

	if !fileExists {
		// Create a new file if it doesn't exist
		f, err = os.Create(testFile)
		if err != nil {
			return "", err
		}
		fmt.Printf("Creating new test file: %s\n", testFile)
	} else {
		// Overwrite the existing file with new test code
		f, err = os.Create(testFile)
		if err != nil {
			return "", err
		}
		fmt.Printf("Updating existing test file: %s\n", testFile)
	}

	// Extract the actual Go code from the response (in case it's wrapped in markdown)
	goCode := extractGoCodeBlocks(testCode)
	if goCode == testCode {
		// If no code blocks were found, use the original content
		goCode = testCode
	}

	// Write the test code to the file
	_, err = f.WriteString(goCode)
	if err != nil {
		return "", err
	}
	defer f.Close()

	return testFile, err
}
