## What This PR Does

Adds dm-verity support to containerd's EROFS snapshotter to provide runtime 
integrity verification for container layers.

## What is the EROFS Differ?

The EROFS differ is a containerd plugin that converts container layer tar files 
into EROFS (Enhanced Read-Only File System) images. 
Instead of extracting tar layers to directories like traditional differs, it creates a 
compressed, read-only filesystem blob that can be mounted directly.

**Important:** The differ runs during first container creation, not during `image pull`. Image pull only downloads tar blobs to the content store.

## How It Works - The Flow

### Phase 0: Image Pull (Downloads Only)
```bash
ctr image pull docker.io/library/busybox:latest
```
- Downloads compressed tar layers from registry
- Stores them in content store: `/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/`
- **Differ does NOT run yet**
- Snapshots directory remains empty

### Phase 1: Layer Creation (by the differ)
**Triggered by:** First container run

```bash
ctr run docker.io/library/busybox:latest mycontainer
```

`ctr run` calls containerd to unpack the image:
- snapshotter.Prepare()
- differ.Apply()
- snapshotter.Commit()

1. **Snapshotter prepares empty snapshot**
   - Creates an empty directory where the EROFS differ will write the image

2. **EROFS differ runs mkfs.erofs to create EROFS image**
   ```
   running /usr/bin/mkfs.erofs [...] /var/lib/containerd/.../snapshots/70/layer.erofs
   Applied layer using tar conversion mode path=.../snapshots/70/layer.erofs
   ```
   - Reads tar from content store
   - Creates EROFS image at `snapshots/70/layer.erofs`

3. **[NEW] dm-verity formatting happens**
   ```
   Successfully formatted dm-verity layer 
     blockSize=4096 
     hashOffset=4489216 
     rootHash=b576fb772077f697eca5a96e8f6f0bc3cbc1d408e53e7c8b6da7d28d91146e06
     size=4489216
   ```
   - Generates Merkle hash tree
   - Appends hash tree to end of layer.erofs (at offset 4489216)
   - Saves roothash and hash offset (byte position where the superblock + hash tree will start) to `layer.erofs.dmverity`:
   - Make a call to the veritysetup-go library
     ```json
     {
       "roothash": "b576fb772077f697eca5a96e8f6f0bc3cbc1d408e53e7c8b6da7d28d91146e06",
       "hashoffset": 4489216
     }
     ```

4. **Snapshotter commits the snapshot**
   ```
   commit snapshot key="extract-..." name="sha256:e14542..." snapshotter=erofs
   ```
   - Snapshot 70 is now ready with layer.erofs + layer.erofs.dmverity

### Phase 2: Runtime Mounting (by the snapshotter + mount handler)
**Triggered by:** Container creation (after unpack is complete)

- Once all layers are committed, the image is ready to use.
- When a container is created, snapshotter.Prepare() is called to create a new active snapshot for the container - for the containers own writable layer
- Then snapshotter.Mount() is called to get the Mount specs

1. **Snapshotter prepares container snapshot**
   ```
   prepare snapshot key=bb7 parent="sha256:e14542..." snapshotter=erofs
   get snapshot mounts key=bb7 snapshotter=erofs
   ```
   - Creates writable layer on top of base layer (snapshot 70)
   - Return mount specifications

2. **Mount manager activates mounts**
   ```
   activate mounts mounts=2 name=readonly-fs-398324540-IC7v
   activating mount mounts="[{erofs .../snapshots/70/layer.erofs [ro loop]} ...]"
   ```
   - Mount 0: EROFS base layer (read-only)
   - Mount 1: OverlayFS (writable layer on top)
   - For each mount type, check is there is a registered handler 

3. **[NEW] EROFS mount handler detects dm-verity metadata**
   ```
   detected dm-verity metadata, setting up dm-verity device 
     source=.../snapshots/70/layer.erofs
   opening dm-verity device 
     device-name=containerd-erofs-70 
     hash-offset=4489216
   ```
   - Mount handler checks for `.dmverity` metadata file
   - When found, calls `dmverity.Open()` to create the device

4. **[NEW] dm-verity device creation** (inside `dmverity.Open()`)
   - Reads dm-verity parameters from superblock at hash offset
   - Attaches layer.erofs to loop device (/dev/loop9)
   - Creates device-mapper target with hash tree configuration
   - Loads verity table with root hash and block sizes
   - Activates the dm-verity device
   ```
   Target params: 1 /dev/loop9 /dev/loop9 4096 4096 1096 1097 sha256 
                  b576fb772077f697eca5a96e8f6f0bc3cbc1d408e53e7c8b6da7d28d91146e06 
                  0000000000000000000000000000000000000000000000000000000000000000
   dm-verity device created successfully device=/dev/mapper/containerd-erofs-70
   ```

5. **EROFS filesystem mounted on dm-verity device**
   ```
   stored dm-verity device for cleanup 
     device=containerd-erofs-70 
     mount-point=/run/containerd/io.containerd.mount-manager.v1.bolt/t/16/1
   ```
   - EROFS mounted from `/dev/mapper/containerd-erofs-70`

6. **Container starts with verified filesystem**
   - Container sees OverlayFS with dm-verity-protected base layer
   - Writes go to upper layer
   - Reads from base are cryptographically verified


### Phase 3: Container Cleanup
**When container stops:**

```
deactivate mounts name=readonly-fs-398324540-IC7v
closing dm-verity device after unmount device=containerd-erofs-70
dm-verity device closed successfully device=containerd-erofs-70
```
- Mount manager calls EROFS handler's Unmount()
- Handler removes dm-verity device
- Loop device is freed
- Clean shutdown, ready for next container


## Configuration Details

### EROFS Differ Configuration

The EROFS differ is configured in containerd's config.toml:

```toml
[plugins."io.containerd.differ.v1.erofs"]
  # Enable dm-verity hash tree generation during layer creation
  enable_dmverity = true
  
  # Enable tar-index mode (preserves original tar alongside EROFS index)
  enable_tar_index = false  # default: false
```

**Configuration options:**

1. **`enable_dmverity`** (boolean, default: false)
   - When `true`: Differ generates Merkle hash tree and appends it to layer.erofs
   - Creates `.dmverity` metadata file with root hash and hash offset

2. **`enable_tar_index`** (boolean, default: false)
   - When `true`: Stores original tar + EROFS index (tar-index mode)
   - When `false`: Extracts tar and creates standard EROFS filesystem


**Interaction:**
- Both options can be enabled together
- dm-verity works with both modes (regular and tar-index)
- Differ automatically selects appropriate block sizes:
  - Regular mode: 4096 bytes (standard page size)
  - Tar-index mode: 512 bytes (dm-verity logical_block_size constraint)

### EROFS Snapshotter Configuration

The EROFS snapshotter is configured in containerd's config.toml:

```toml
[plugins."io.containerd.snapshotter.v1.erofs"]
  # Control dm-verity behavior at mount time
  dmverity_mode = "auto"  # Options: "auto", "on", "off"
```

**dm-verity Configuration modes:**

1. **`dmverity_mode = "auto"`** (default, recommended)
   - **Behavior**: Uses dm-verity if `.dmverity` metadata exists, otherwise regular EROFS

2. **`dmverity_mode = "on"`** (strict enforcement)
   - **Behavior**: Requires `.dmverity` metadata for ALL layers
   - **Failure**: Mounting fails with error if metadata is missing

3. **`dmverity_mode = "off"`** (disable completely)
   - **Behavior**: Never uses dm-verity, even if metadata exists
   - **Note**: Still creates regular EROFS mounts


## Code Components

1. **internal/dmverity/** - Pure Go dm-verity operations
   - Uses veritysetup-go (no external tools needed!)
   - Open() - creates dm-verity device
   - Close() - removes dm-verity device
   - ReadMetadata() - reads .dmverity JSON files

2. **plugins/diff/erofs/** - Layer creation
   - WithDmverity() option enables hash tree generation
   - Formats layer with dm-verity during Apply()
   - Works with both regular and tar-index modes

3. **plugins/mount/erofs/** - Runtime mounting
   - NewErofsMountHandler() registered with mount manager
   - Mount() - detects .dmverity, creates device, mounts
   - Unmount() - cleans up dm-verity device
   - Tracks devices per mount point

4. **plugins/snapshots/erofs/** - Snapshotter config
   - WithDmverityMode() option ("off"/"on")
   - createErofsMount() creates mount specs
   - No dm-verity logic! Just creates regular mounts


### Why This Design

**Separation of Concerns:**
```
Snapshotter:      "Here's an EROFS file to mount"
Mount Manager:    "Let me find the right handler"
Mount Handler:    "I'll handle dm-verity transparently"
Runtime:          "Cool, filesystem is ready"
```

**No special knowledge required:**
- Snapshotter doesn't know about dm-verity
- Mount manager doesn't know about dm-verity
- Only the EROFS mount handler knows about dm-verity
- Runtime sees regular EROFS mount

**Automatic detection:**
- Check for `.dmverity` file → exists? → use dm-verity
- No `.dmverity` file → regular EROFS mount
- No configuration needed per-image!

**Clean lifecycle:**
```
Mount:   Handler creates dm-verity device
Use:     Container reads verified data
Unmount: Handler removes dm-verity device
```

### Registration: How Mount Manager Finds the Handler

**At containerd startup:**

```go
// In plugins/mount/erofs/plugin.go
func init() {
    registry.Register(&plugin.Registration{
        Type: plugins.MountHandlerPlugin,
        ID:   "erofs",
        InitFn: func(ic *plugin.InitContext) (interface{}, error) {
            // Create and return EROFS mount handler
            return NewErofsMountHandler(), nil
        },
    })
}
```

**Mount manager initialization:**

```go
// In containerd startup
mountManager := manager.NewManager(
    db,
    targetDir,
    manager.WithMountHandler("erofs", erosMountHandler),
)
```

**Now mount manager has a map:**
```go
handlers = map[string]Handler{
    "erofs": erofsMountHandler,
    // other handlers...
}
```

**When it sees `Type="erofs"`:**
```go
if handler := handlers["erofs"]; handler != nil {
    handler.Mount(...)  // Delegates to our handler!
}
```

## Testing Coverage

- Unit tests: mount creation logic
- Integration tests: full differ → snapshotter → mount flow
- Tests both regular mode and tar-index mode
- Verifies file contents are readable (proves verification works)
- Tests cleanup (devices removed on unmount)