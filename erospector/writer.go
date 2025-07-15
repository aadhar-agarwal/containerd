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
			// Remove any package declaration from extracted code blocks
			code := match[1]
			code = regexp.MustCompile(`(?m)^package\s+\w+\s*`).ReplaceAllString(code, "")
			// Remove any import statements
			code = regexp.MustCompile(`(?ms)^import\s+\(\s*(.*?)\s*\)\s*`).ReplaceAllString(code, "")
			code = regexp.MustCompile(`(?m)^import\s+\".*?\"\s*`).ReplaceAllString(code, "")
			result.WriteString(code)
			result.WriteString("\n\n")
		}
	}

	return result.String()
}

func WriteTestFile(sourceFile string, funcName string, testCode string) error {
	// Get the directory where the source file is located
	sourceDir := filepath.Dir(sourceFile)

	// Get the base filename without extension
	base := strings.TrimSuffix(filepath.Base(sourceFile), ".go")

	// Create the test file path in the same directory as the source file
	testFile := filepath.Join(sourceDir, base+"_test.go")

	// Extract Go code from the GPT response
	goCode := extractGoCodeBlocks(testCode)

	// If no code blocks were found, use the original content but add a warning
	if goCode == testCode {
		goCode = "// WARNING: No Go code blocks were detected in the GPT response\n" +
			"// The following content may need manual editing to be executable\n\n" +
			testCode
	}

	// Check if the file exists
	fileExists := false
	_, err := os.Stat(testFile)
	if err == nil {
		fileExists = true
	}

	var f *os.File
	var packageName string
	var existingContent []byte

	if !fileExists {
		// Create a new file if it doesn't exist
		f, err = os.Create(testFile)
		if err != nil {
			return err
		}

		// Get the package name from the source file
		packageName, err = getPackageName(sourceFile)
		fmt.Print(packageName)

		header := fmt.Sprintf("package %s\n\nimport (\n\t\"testing\"\n)\n\n", packageName)
		_, err = f.WriteString(header)
		if err != nil {
			f.Close()
			return err
		}
	} else {
		// Read existing file to check for duplicate functions
		existingContent, err = os.ReadFile(testFile)
		if err != nil {
			return err
		}

		// Check if the function test already exists
		funcTestPattern := fmt.Sprintf("func Test%s", funcName)
		if strings.Contains(string(existingContent), funcTestPattern) {
			// Skip adding this test as it already exists
			return fmt.Errorf("test for %s already exists in %s", funcName, testFile)
		}

		// Open existing file in append mode
		f, err = os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
	}
	defer f.Close()

	// Add a comment indicating which function this test is for
	testHeader := fmt.Sprintf("\n// Test for %s\n", funcName)
	_, err = f.WriteString(testHeader + goCode)

	return err
}

// getPackageName reads the first line of the file to determine the package name
func getPackageName(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Read first few hundred bytes which should be enough to get package declaration
	buffer := make([]byte, 500)
	_, err = file.Read(buffer)
	if err != nil {
		return "", err
	}

	// Find the package declaration
	re := regexp.MustCompile(`package\s+(\w+)`)
	matches := re.FindSubmatch(buffer)
	if len(matches) >= 2 {
		return string(matches[1]), nil
	}

	return "", fmt.Errorf("package name not found")
}
