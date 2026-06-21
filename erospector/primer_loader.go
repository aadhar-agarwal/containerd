package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FindGoFilesInDirectories finds all .go files in the specified directories recursively
func FindGoFilesInDirectories(dirs []string) ([]string, []string) {
	var files []string
	var missingDirs []string

	for _, dir := range dirs {
		// Check if directory exists first
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			missingDirs = append(missingDirs, dir)
			fmt.Printf("Warning: Directory doesn't exist: %s\n", dir)
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("Warning: Error accessing path %s: %v\n", path, err)
				return nil // Continue walking even if there's an error with this file
			}

			// Skip directories themselves
			if info.IsDir() {
				return nil
			}

			// Only include .go files
			if filepath.Ext(path) == ".go" {
				files = append(files, path)
			}

			return nil
		})

		if err != nil {
			fmt.Printf("Warning: Error walking directory %s: %v\n", dir, err)
		}
	}

	return files, missingDirs
}

func LoadPrimerFromFiles(files []string) (string, error) {
	var primer strings.Builder

	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to read %s: %w", path, err)
		}

		primer.WriteString(fmt.Sprintf("\n--- BEGIN FILE: %s ---\n", filepath.Base(path)))
		primer.WriteString(string(content))
		primer.WriteString(fmt.Sprintf("\n--- END FILE: %s ---\n\n", filepath.Base(path)))
	}

	return primer.String(), nil
}
