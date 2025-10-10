# Root Hash File Support

## Overview

The `--root-hash-file` option allows saving the generated root hash to a file during the `format` operation, instead of only printing it to stdout.

## Usage

### Basic Example

```go
opts := dmverity.DefaultDmverityOptions()
opts.RootHashFile = "/tmp/root-hash.txt"

info, err := dmverity.Format("/dev/loop0", "/dev/loop1", &opts)
if err != nil {
    log.Fatal(err)
}

// Root hash is available in info.RootHash
// AND has been saved to /tmp/root-hash.txt
fmt.Printf("Root hash: %s\n", info.RootHash)
```

## Benefits

1. **Automation-Friendly**: Eliminates need to parse stdout
2. **Secure Storage**: Hash can be written directly to secure location
3. **Scripting**: Easier to use in shell scripts and CI/CD pipelines
4. **Persistence**: Hash is saved even if program crashes after formatting

## Implementation Details

### When RootHashFile is Specified

1. `--root-hash-file <path>` is passed to veritysetup
2. veritysetup writes the root hash (hex-encoded) to the specified file
3. After formatting completes, we read the file to populate `FormatOutputInfo.RootHash`
4. The hash is validated using `ValidateRootHash()`

### File Format

The file contains the root hash as a hex-encoded string (no newlines or whitespace at the end after trimming):

```
4d8f71f8a5b9c3e2f7a1d6b4e9c8a7f5d2e1b3c4a5e7d9f8b6c3a2e1f7d8b9a4
```

For SHA-256: 64 hex characters (32 bytes)
For SHA-512: 128 hex characters (64 bytes)

### Fallback Behavior

If `RootHashFile` is NOT specified:
- Root hash is parsed from stdout (existing behavior)
- `ParseFormatOutput()` extracts it from the "Root hash:" line

If `RootHashFile` IS specified:
- Root hash may not appear in stdout
- We read it from the file after formatting
- Both sources are validated with `ValidateRootHash()`

## Error Handling

Possible errors when using RootHashFile:

```go
// File cannot be created (permissions, path doesn't exist)
"failed to format dm-verity device: ..."

// File cannot be read after formatting
"failed to read root hash from file \"/path\": ..."

// File contains invalid hash
"root hash from file is invalid: must be a valid hex string"
```

## Security Considerations

1. **File Permissions**: Ensure the target file has appropriate permissions
2. **Path Validation**: Validate the path before passing to Format()
3. **Atomic Writes**: veritysetup writes atomically, but cleanup on failure is caller's responsibility
4. **Cleanup**: Consider removing the file if Format() fails

## Example: Secure Usage

```go
// Create a secure temporary file
tmpFile, err := os.CreateTemp("", "root-hash-*.txt")
if err != nil {
    return err
}
defer os.Remove(tmpFile.Name()) // Cleanup on any error
tmpFile.Close()

// Use it for root hash
opts := dmverity.DefaultDmverityOptions()
opts.RootHashFile = tmpFile.Name()

info, err := dmverity.Format(dataDevice, hashDevice, &opts)
if err != nil {
    return fmt.Errorf("format failed: %w", err)
}

// Move to permanent location if needed
if err := os.Rename(tmpFile.Name(), "/secure/location/root-hash"); err != nil {
    return err
}
```

## Compatibility

- Requires veritysetup version 1.0 or later
- Option is ignored for `Open()` and `Close()` commands (format-only)
- Works with or without `--no-superblock` flag
- Compatible with all hash algorithms (sha256, sha512, sha1)

## Testing

When testing, verify:
1. File is created with correct permissions
2. File contains valid hex-encoded hash
3. Hash in file matches hash in FormatOutputInfo
4. File is readable after formatting
5. Error handling when file path is invalid
