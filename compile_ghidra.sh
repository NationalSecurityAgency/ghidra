#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a directory exists
dir_exists() {
    [ -d "$1" ]
}

# Check if Git is installed
if ! command_exists git; then
    echo "Git is not installed. Please install Git and rerun this script."
    exit 1
fi

# Check if Java JDK is installed
if ! command_exists javac; then
    echo "Java JDK is not installed. Please install Java JDK and rerun this script."
    exit 1
fi

# Check if Apache Ant is installed
if ! command_exists ant; then
    echo "Apache Ant is not installed. Please install Apache Ant and rerun this script."
    exit 1
fi

# Prompt user for Ghidra version
echo "Please provide the version of Ghidra you want to compile (e.g., 11.0.3):"
read -r GHIDRA_VERSION

# Clone Ghidra repository
GHIDRA_DIR="ghidra_$GHIDRA_VERSION"
GHIDRA_REPO_URL="https://github.com/NationalSecurityAgency/ghidra.git"
echo "Cloning Ghidra repository..."
git clone --depth 1 --branch Ghidra_"$GHIDRA_VERSION"_build "$GHIDRA_REPO_URL" "$GHIDRA_DIR"

# Check if clone was successful
if ! dir_exists "$GHIDRA_DIR"; then
    echo "Failed to clone Ghidra repository. Aborting."
    exit 1
fi

# Compile Ghidra
echo "Compiling Ghidra..."
cd "$GHIDRA_DIR"
ant

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Failed to compile Ghidra. Aborting."
    exit 1
fi

# Set up Ghidra command line tool
echo "Setting up Ghidra command line tool..."
GHIDRA_SCRIPT="ghidraRun"
echo "#!/bin/bash" > "$GHIDRA_SCRIPT"
echo 'java -Xmx4G -jar "$0/support/analyzeHeadless.jar" "$@"' >> "$GHIDRA_SCRIPT"
chmod +x "$GHIDRA_SCRIPT"

# Add Ghidra to PATH
echo "Adding Ghidra to PATH..."
GHIDRA_PATH="$(pwd)"
echo "export PATH=\"\$PATH:$GHIDRA_PATH\"" >> ~/.bashrc

echo "Ghidra compilation and setup complete. You can now use 'ghidra' command in the terminal."
