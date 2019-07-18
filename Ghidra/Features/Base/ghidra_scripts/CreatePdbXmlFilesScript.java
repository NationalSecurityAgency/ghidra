/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.*;

/**
 *
 * Asks user for a single .pdb file or a directory that contains .pdb files (search for
 * files is recursive).
 *
 * Parses each .pdb file and creates a corresponding .pdb.xml file in the same location as
 * the original file. The .pdb.xml files can be used to apply debugging information when
 * running Ghidra on non-Windows systems.
 * 
 * This script can only be run on Windows and using the headed (GUI) version of Ghidra.
 *
 */
public class CreatePdbXmlFilesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		// Error if not running on Windows
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.WINDOWS) {
			popup("Aborting: This script is for use on Windows only.");
			return;
		}

		// Get appropriate pdb.exe file
		String pdbExeLocation = Application.getOSFile("pdb.exe").getAbsolutePath();

		List<String> choices = Arrays.asList("single file", "directory of files");
		String fileOrDir = askChoice("PDB file or directory",
			"Would you like to operate on a single " + ".pdb file or a directory of .pdb files?",
			choices, choices.get(1));

		File pdbParentDir;
		String pdbName;

		int filesCreated = 0;

		try {
			if (fileOrDir.equals(choices.get(0))) {
				File pdbFile = askFile("Choose a PDB file", "OK");

				if (!pdbFile.exists()) {
					popup(pdbFile.getAbsolutePath() + " is not a valid file.");
					return;
				}

				if (!pdbFile.getName().endsWith(".pdb")) {
					popup("Aborting: Expected input file to have extension of type .pdb (got '" +
						pdbFile.getName() + "').");
					return;
				}

				pdbParentDir = pdbFile.getParentFile();
				pdbName = pdbFile.getName();

				println("Processing: " + pdbFile.getAbsolutePath());

				runPdbExe(pdbExeLocation, pdbParentDir, pdbName, pdbFile.getAbsolutePath());

				filesCreated = 1;
			}
			else {
				// Do recursive processing
				File pdbDir = askDirectory(
					"Choose PDB root folder (performs recursive search for .pdb files)", "OK");

				// Get list of files to process
				List<File> pdbFiles = new ArrayList<>();
				getPDBFiles(pdbDir, pdbFiles);

				int createdFilesCounter = 0;

				for (File childPDBFile : pdbFiles) {
					pdbParentDir = childPDBFile.getParentFile();
					pdbName = childPDBFile.getName();

					String currentFilePath = childPDBFile.getAbsolutePath();
					println("Processing: " + currentFilePath);

					runPdbExe(pdbExeLocation, pdbParentDir, pdbName, currentFilePath);

					createdFilesCounter++;

					if (monitor.isCancelled()) {
						break;
					}
				}

				filesCreated = createdFilesCounter;
			}
		}
		catch (IOException ioe) {
			popup(ioe.getMessage());
		}

		if (filesCreated > 0) {
			popup("Created " + filesCreated + " .pdb.xml file(s).");
		}
	}

	private void runPdbExe(String pdbExeLocation, File pdbParentDir, String pdbName,
			String currentFilePath) throws IOException, InterruptedException {

		ProcessBuilder builder = new ProcessBuilder(pdbExeLocation, currentFilePath);
		File createdFile = new File(pdbParentDir, pdbName + ".xml");
		builder.redirectOutput(createdFile);

		Process currentProcess = builder.start();
		StringBuilder strBuilder = new StringBuilder();

		BufferedReader reader =
			new BufferedReader(new InputStreamReader(currentProcess.getErrorStream()));
		String line = null;

		while ((line = reader.readLine()) != null) {
			strBuilder.append(line);
			strBuilder.append(System.getProperty("line.separator"));
		}

		reader.close();

		int exitValue = currentProcess.waitFor();
		String errorMessage = strBuilder.toString();

		if (errorMessage.length() > 0) {
			if (createdFile.isFile()) {
				createdFile.delete();
			}

			throw new IOException("At file '" + pdbName + "':\n" + errorMessage);
		}

		if (exitValue != 0) {
			if (createdFile.isFile()) {
				createdFile.delete();
			}

			throw new IOException(
				"At file '" + pdbName + "':\nAbnormal termination of 'pdb.exe' process.");
		}
	}

	private void getPDBFiles(File parentDir, List<File> foundFiles) {

		for (File childFile : parentDir.listFiles()) {
			if (childFile.isDirectory()) {
				getPDBFiles(childFile, foundFiles);
			}
			else {
				if (childFile.getName().endsWith(".pdb")) {
					foundFiles.add(childFile);
				}
			}
		}
	}
}
