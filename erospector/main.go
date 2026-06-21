package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Define command-line flags
	var targetFunctions string
	var listOnly bool
	var testMode string

	flag.StringVar(&targetFunctions, "funcs", "", "Comma-separated list of function names to generate tests for (e.g., 'Function1,Function2')")
	flag.StringVar(&targetFunctions, "f", "", "Comma-separated list of function names to generate tests for (short form)")
	flag.BoolVar(&listOnly, "list", false, "Only list available functions without generating tests")
	flag.BoolVar(&listOnly, "l", false, "Only list available functions without generating tests (short form)")
	flag.StringVar(&testMode, "mode", "simple", "Test generation mode: 'simple' or 'test_and_run'")
	flag.StringVar(&testMode, "m", "simple", "Test generation mode: 'simple' or 'test_and_run' (short form)")

	// Parse flags but leave os.Args[0] which is the program name
	flag.CommandLine.Parse(os.Args[1:])

	// After flag parsing, the remaining arguments are in flag.Args()
	if len(flag.Args()) < 1 {
		fmt.Printf("Usage: erospector [options] <path-to-go-file>\n")
		fmt.Printf("\nOptions:\n")
		fmt.Printf("  -funcs, -f <names>    Comma-separated list of function names to generate tests for\n")
		fmt.Printf("  -list, -l             Only list available functions without generating tests\n")
		fmt.Printf("  -mode, -m <mode>      Test generation mode: 'simple' (default) or 'test_and_run'\n")
		fmt.Printf("\nExamples:\n")
		fmt.Printf("  erospector /path/to/file.go                       Generate tests for all functions\n")
		fmt.Printf("  erospector -list /path/to/file.go                 List all functions without generating tests\n")
		fmt.Printf("  erospector -f Func1,Func2 /path/to/file.go        Generate tests only for Func1 and Func2\n")
		fmt.Printf("  erospector -m test_and_run /path/to/file.go       Generate tests with iterative improvement\n")
		return
	}

	filePath := flag.Args()[0]
	funcs, err := ExtractFunctions(filePath)
	if err != nil {
		panic(err)
	}

	// Filter functions if specific names were provided
	var targetFuncs []GoFunction
	if targetFunctions != "" {
		funcNames := strings.Split(targetFunctions, ",")
		funcNameMap := make(map[string]bool)
		for _, name := range funcNames {
			funcNameMap[strings.TrimSpace(name)] = true
		}

		for _, fn := range funcs {
			if funcNameMap[fn.Name] {
				targetFuncs = append(targetFuncs, fn)
			}
		}

		if len(targetFuncs) == 0 {
			fmt.Printf("Warning: None of the specified functions were found in the file.\n")
			fmt.Printf("Available functions in %s:\n", filePath)
			for _, fn := range funcs {
				fmt.Printf("  - %s\n", fn.Name)
			}
			return
		}

		funcs = targetFuncs
	}

	// If list-only mode is enabled, just display functions and exit
	if listOnly {
		fmt.Printf("\nAvailable functions:\n")
		for i, fn := range funcs {
			fmt.Printf("%d. %s\n", i+1, fn.Name)
		}
		return
	}

	// Get the absolute path to the repo root directory
	repoRoot := "/home/aadhar/repos/containerd/"

	// Directories to scan recursively for Go files
	directoriesWithGoFiles := []string{
		filepath.Join(repoRoot, "plugins/snapshots/erofs/"),
		filepath.Join(repoRoot, "plugins/diff/erofs/"),
		filepath.Join(repoRoot, "core/diff/"),
		filepath.Join(repoRoot, "core/snapshots/"),
		filepath.Join(repoRoot, "internal/erofsutils/"),
	}

	// Find all Go files in the specified directories
	primerFiles, missingDirs := FindGoFilesInDirectories(directoriesWithGoFiles)

	if len(missingDirs) > 0 {
		fmt.Printf("\nWarning: The following directories could not be found:\n")
		for _, dir := range missingDirs {
			fmt.Printf("  - %s\n", dir)
		}
	}

	// Load all the files into the primer
	primer, err := LoadPrimerFromFiles(primerFiles)
	if err != nil {
		fmt.Printf("Warning: Error loading primer from files: %v\n", err)
	}

	// fmt.Printf("Preloaded the following files for context:\n")
	// for _, file := range primerFiles {
	// 	fmt.Printf("  - %s\n", file)
	// }

	// Read the source file content once
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading source file: %v\n", err)
		return
	}
	fileCodeString := string(fileContent)

	// Validate test mode
	if testMode != "simple" && testMode != "test_and_run" {
		fmt.Printf("Error: Invalid test mode '%s'. Must be 'simple' or 'test_and_run'\n", testMode)
		return
	}

	fmt.Printf("Using test generation mode: %s\n", testMode)

	testCode, err := AskGPTForTestPythonWithMode(fileCodeString, primer, testMode, filePath)
	if err != nil {
		fmt.Printf("Error from GPT: %s\n", err)
		return
	}

	_, err = WriteTestFile(filePath, testCode)
	if err != nil {
		fmt.Printf("File write error: %s\n", err)
		return
	}
	fmt.Printf("Test written\n")
}
