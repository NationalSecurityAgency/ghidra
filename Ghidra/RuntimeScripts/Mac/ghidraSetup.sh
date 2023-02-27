#!/bin/bash
#----------------------------------------
# Ghidra Setup script to locally build the app and create a new run script for MacOS
#----------------------------------------

# READ THIS FIRST -----------------------
# 1. Install Java 17+ & Gradle 7.3+
# If you don't know how to do this step, install brew: https://brew.sh
# Using brew you can install the latest JDK by cmd: brew install openjdk
# Using brew you can install the latest Gradle by cmd: brew install gradle

# 2. Make this script executable.
# chmod +x ghidraSetuo.sh

# 3. Run it
#./ghidraSetup.sh
# ---------------------------------------

# Clear the log file if it exists
SHAREABLE_LOG_FILE=anon-public.log
rm -f "$SHAREABLE_LOG_FILE"

# Function to print an anonymized version of the given string
anon="[[anonymized-user]]"
echo -e "🐲 \n---> Anonymizing your username $USER as $anon in all copied output to log file: $SHAREABLE_LOG_FILE"
function anonymize_string {
  local input_string="$1"
  local anonymize_username="${2:-true}"
  if [ "$anonymize_username" == "true" ]; then
    echo "$input_string" | sed -e "s/$USER/$anon/g" -e "s/$HOSTNAME/PCNAME/g"
  else
    echo "$input_string"
  fi
}

# Redirect anonymized output to shareable log file
echo -e "🐲 \n---> Redirecting anonymized output to shareable log file: $SHAREABLE_LOG_FILE"
exec > >(while read line; do
  anonymize_string "$line" true >>"$SHAREABLE_LOG_FILE"
  echo "$line"
done)

mac_script_dir=$(pwd)
echo -e "Script ran at $(date) in directory: $mac_script_dir\nShareable log file will be output as '$SHAREABLE_LOG_FILE'"

ARCH=$(uname -m)
echo -e "🐲 \n---> Architecture: $ARCH"

# Navigating back out to root directory
cd ../../../
root_dir=$(pwd)
echo -e "Root directory: $root_dir"
builddistpath="$root_dir/build/dist"


echo -e "🐲 \n---> Exposing additional environment parameters for future troubleshooting reference..."
echo "These details are not necessary for running Ghidra, but may help when sharing logs."

# Prints the version number of the LLDB (LLVM Debugger) debugger for C/C++/Objective-C/Swift programs.
# It's a collection of modular and reusable compiler/toolchain technologies
echo -e "\nPrinting the version of your LLDB..."
lldb --version

# Check if LLVM_HOME is set
if [[ -z "${LLVM_HOME}" ]]; then
  echo "- LLVM_HOME is not set."
else
  echo "- LLVM_HOME: ${LLVM_HOME}"
fi

# Check if LLVM_BUILD is set
if [[ -z "${LLVM_BUILD}" ]]; then
  echo "- LLVM_BUILD is not set."
else
  echo "- LLVM_BUILD: ${LLVM_BUILD}"
fi

# Check if GRADLE_HOME is set
if [[ -z "${GRADLE_HOME}" ]]; then
  echo "- GRADLE_HOME is not set."
else
  echo "- GRADLE_HOME: ${GRADLE_HOME}"
fi

# Check if JAVA_HOME is set
if [[ -z "${JAVA_HOME}" ]]; then
  echo "- JAVA_HOME is not set."
else
  echo "- JAVA_HOME: ${JAVA_HOME}"
fi

echo -e "🐲 \n---> Checking installed dev tools..."
echo "🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡"
echo "The recommended version of Java is JDK 17 or above due to bugs and security issues."
# Check if Java is installed
if command -v java >/dev/null 2>&1; then
  echo "✔️Java is already installed."
  java -version
else
  echo "⛔Error: Java is not installed. You should probably install Java before proceeding."
  exit
fi

"Note: JDK 17 64-bit (jdk17) is required."
echo "🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡"

# Check if Gradle is installed
echo "The recommended version of Gradle is Gradle 7.3+ or above for compatibility with Java 17+."
if ! command -v gradle &>/dev/null; then
  echo "⛔Error: Gradle is not installed."
  exit 1
fi
echo "Note: Gradle 7.3+ is required."
echo "🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡"

echo -e "🐲 \n---> Download non-Maven Central dependencies, creating a dependencies directory in the repository root..."
echo -e "Additional info at Ghidra Dev Guide: https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md"
gradle -I gradle/support/fetchDependencies.gradle init

echo -e "🐲 \n---> Build Ghidra to [build/dist]..."
if ! gradle buildGhidra; then
  echo "⛔Error: Ending script as the Gradle build has failed."
  exit 1
fi

# Check if the build/dist subfolder exists
if [ -d "build/dist" ]; then
  # List the files inside the build/dist subfolder
  echo "✔️The build/dist subfolder has been created. The following files are inside it:"
  ls -l build/dist
  echo "Navigating into [build/dist]..."
  cd build/dist
else
  echo "⛔Error: The build/dist subfolder does not exist. Ending script..."
  exit 1
fi

echo -e "Build Distribution directory: $builddistpath"

# Find the zip file with 'ghidra' in its name
ghidradevzipfile=$(find . -maxdepth 1 -type f -name '*ghidra*.zip' -print -quit)

# Check if a zip file was found
if [[ -n "$ghidradevzipfile" ]]; then

  echo -e "🐲 \n---> Unzip GhidraDev file..."
  # Extract the folder name from the output of the unzip command
  ghidradevfolder=$(unzip -qql "$ghidradevzipfile" | awk 'NR==1{print $NF}' | sed 's|/$||')
  echo "Found folder [$ghidradevfolder] in $ghidradevzipfile"

  # Delete if ghidra dev folder from a previous unzip is already here
  if [[ -d "$ghidradevfolder" ]]; then
    # Delete the folder and all its contents
    echo "Found a folder of same name [$ghidradevfolder] from previous unzip in this directory."
    rm -rf "$ghidradevfolder"
    echo "Deleted existing folder $ghidradevfolder."
  fi

  echo "Unzipping Ghidra file [$ghidradevzipfile]..."
  unzip "$ghidradevzipfile"

  # Check if the ghidradevfolder exists
  if [[ -d "$ghidradevfolder" ]]; then
    echo "✔️The zip file '$ghidradevzipfile' has been unzipped and the folder '$ghidradevfolder' is available."
  else
    echo "⛔Error: Unzip process ended, for some reason the folder '$ghidradevfolder' does not exist."
    exit 1
  fi
else
  echo "⛔Error: No zip file with 'ghidra' in its name was found in the current directory."
  exit 1
fi

# Navigating into ghidra-dev folder"
cd $ghidradevfolder

ghidradevpath="$builddistpath/$ghidradevfolder"

# Check if 'ghidraRun' script exists and is executable
if [ -x "ghidraRun" ]; then
  echo "✔️The built ghidraRun script we needed is present. Great!!!"
else
  echo "⛔Error: ghidraRun script was not found or is not executable!"
  exit 1
fi

newrunscriptname=startGhidra.sh
echo -e "🐲 \n---> Creating a new $newrunscriptname script in the Mac directory: $mac_script_dir"
echo "It essentially launches the original script unzipped in the built ghidra-dev folder we just built."
cd $mac_script_dir
touch $newrunscriptname

if [ -f $newrunscriptname ]; then
  echo "$newrunscriptname file created successfully @ $(pwd)/$newrunscriptname"
fi

# Add content to the new file
cat <<EOT >>$newrunscriptname
#!/bin/bash

# Change to the directory where the other script is located
cd "$ghidradevpath"
# Run the original ghidraRun script
./ghidraRun

# Optional way to run original script in one line instead of two
#$ghidradevpath/ghidraRun
EOT

if [ -f $newrunscriptname ]; then
  echo "✔️[$newrunscriptname] file generated successfully @ $mac_script_dir."
else
  echo "⛔Error: Failed to generate $newrunscriptname file. Exiting."
  exit 1
fi

# Make the new file executable
chmod +x $newrunscriptname

# Clean up to save unused space
ghidradevzipfilepath="$builddistpath/$ghidradevzipfile"
# check if it still exists
if [ -f "$ghidradevzipfilepath" ]; then
  # delete it
  rm -f "$ghidradevzipfilepath"
  echo "Deleting zip file [$ghidradevzipfile] since we have extracted the files we needed successfully."
fi

# Display a message indicating that the script file has been created
echo "✔️Script file [$newrunscriptname] has been created and made executable."

echo "🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲"
echo "✔️SUCCESS!"
echo "🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲"
echo "You can now run the app by running the new $newrunscriptname script."
echo "Script Location: $mac_script_dir"
echo "🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲🐲"
