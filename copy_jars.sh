#!/bin/bash

# Destination directory
DEST_DIR="/home/matteius/GhidraMCP/lib"

# Array of JAR files to copy with their source paths
declare -a JARS=(
    "Ghidra/Features/Base/lib/Base.jar"
    "Ghidra/Features/Decompiler/lib/Decompiler.jar"
    "Ghidra/Framework/Docking/lib/Docking.jar"
    "Ghidra/Framework/Generic/lib/Generic.jar"
    "Ghidra/Framework/Project/lib/Project.jar"
    "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar"
    "Ghidra/Framework/Utility/lib/Utility.jar"
    "Ghidra/Framework/Gui/lib/Gui.jar"
)

# Check if destination directory exists, create if it doesn't
if [ ! -d "$DEST_DIR" ]; then
    echo "Creating destination directory: $DEST_DIR"
    mkdir -p "$DEST_DIR"
fi

# Counter for successful copies
SUCCESS_COUNT=0
FAIL_COUNT=0

echo "Starting copy operation..."
echo "Destination: $DEST_DIR"
echo "----------------------------------------"

# Copy each JAR file
for jar_path in "${JARS[@]}"; do
    if [ -f "$jar_path" ]; then
        # Extract just the filename from the path
        jar_name=$(basename "$jar_path")
        
        echo "Copying $jar_path -> $DEST_DIR/$jar_name"
        
        if cp "$jar_path" "$DEST_DIR/"; then
            echo "  ✓ Successfully copied $jar_name"
            ((SUCCESS_COUNT++))
        else
            echo "  ✗ Failed to copy $jar_name"
            ((FAIL_COUNT++))
        fi
    else
        echo "  ⚠ Warning: $jar_path not found"
        ((FAIL_COUNT++))
    fi
done

echo "----------------------------------------"
echo "Copy operation complete!"
echo "Successfully copied: $SUCCESS_COUNT files"
echo "Failed/Not found: $FAIL_COUNT files"

# Exit with error code if any files failed
if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
