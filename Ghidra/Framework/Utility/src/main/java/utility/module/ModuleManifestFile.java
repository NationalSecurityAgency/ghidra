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
package utility.module;

import java.io.*;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

public class ModuleManifestFile {
	public final static String MODULE_MANIFEST_FILE_NAME = "Module.manifest";

	private static final String NAME_IDENTIFIER = "MODULE NAME:";
	private static final String DEPENDENCY_IDENTIFIER = "MODULE DEPENDENCY:";
	private static final String MODULE_FILE_LICENSE = "MODULE FILE LICENSE:";
	private static final String EXCLUDE_FROM_GHIDRA_JAR = "EXCLUDE FROM GHIDRA JAR";
	private static final String DATA_SEARCH_IGNORE_DIR = "DATA SEARCH IGNORE DIR:";
	private static final String MODULE_DIR_IDENTIFIER = "MODULE DIR:";
	private static final String FAT_JAR = "FAT JAR:";
//	private static final String EXTENSION_SUFFIX = "EXTENSION SUFFIX:";
//	private static final String REQUIRES_CLASS_SEARCH = "REQUIRES CLASS SEARCH:";
//	private static final String OWNER_IDENTIFIER = "MODULE DIR:";
//	private static final String RSRC_IDENTIFIER = "MODULE DIR:";
//	private static final String DATA_IDENTIFIER = "MODULE DIR:";
//	private static final String PLAF_IDENTIFIER = "MODULE DIR:";

	private static final String COMMENT_IDENTIFIER = "#";

	private String moduleName;
	private boolean excludeFromGhidraJar;
	private Map<String, String> fileIPMap = new HashMap<String, String>();

	private Set<String> dataSearchIgnoreDirs = new HashSet<String>();
	private Set<String> fatJars = new HashSet<>();

	public ModuleManifestFile(File moduleRootDir) throws IOException {
		this(new ResourceFile(moduleRootDir));
	}

	public ModuleManifestFile(ResourceFile moduleRootDir) throws IOException {
		ResourceFile file = new ResourceFile(moduleRootDir, MODULE_MANIFEST_FILE_NAME);

		if (!file.exists()) {
			throw new FileNotFoundException("Missing module manifest file:" +
				file.getAbsolutePath());
		}

		List<String> lines = FileUtilities.getLines(file);

		int lineNumber = 1;
		for (String line : lines) {
			processLine(file, line, lineNumber++);
		}
	}

	public static boolean hasModuleManifest(File moduleRootDir) {
		File file = new File(moduleRootDir, MODULE_MANIFEST_FILE_NAME);
		return file.exists();
	}

	public boolean excludeFromGhidraJar() {
		return excludeFromGhidraJar;
	}

	public Map<String, String> getModuleFileIPs() {
		return Collections.unmodifiableMap(fileIPMap);
	}

	private void processLine(ResourceFile file, String configLine, int lineNumber)
			throws IOException {
		String trimmedLine = configLine.trim();
		if (trimmedLine.length() == 0) {
			return; // ignore empty lines.
		}

		else if (trimmedLine.startsWith(NAME_IDENTIFIER)) {
			processNameLine(trimmedLine);
		}
		else if (trimmedLine.startsWith(DEPENDENCY_IDENTIFIER)) {
			// ignore for now
		}
		else if (trimmedLine.startsWith(EXCLUDE_FROM_GHIDRA_JAR)) {
			excludeFromGhidraJar = true;
		}
		else if (trimmedLine.startsWith(MODULE_FILE_LICENSE)) {
			processModuleFileLicense(trimmedLine);
		}
		else if (trimmedLine.startsWith(COMMENT_IDENTIFIER)) {
			// this is a comment line--ignore!
		}
		else if (trimmedLine.startsWith(DATA_SEARCH_IGNORE_DIR)) {
			processDataSearchIgnoreDir(trimmedLine);
		}
		else if (trimmedLine.startsWith(MODULE_DIR_IDENTIFIER)) {
			// do nothing for now
		}
		else if (trimmedLine.startsWith(FAT_JAR)) {
			processFatJar(trimmedLine);
		}
		else {
			String message =
				"Module manifest file error on line " + (lineNumber + 1) + " of file: " + file +
					"\n\t-> Invalid line encountered: " + trimmedLine;
			Msg.debug(this, message);
		}
	}

	private void processDataSearchIgnoreDir(String trimmedLine) {
		String ignoreDirName = trimmedLine.substring(DATA_SEARCH_IGNORE_DIR.length()).trim();
		dataSearchIgnoreDirs.add(ignoreDirName);
	}

	private void processModuleFileLicense(String line) throws IOException {
		String fileAndIPLine = line.substring(MODULE_FILE_LICENSE.length()).trim();
		int firstSpace = fileAndIPLine.indexOf(' ');
		if (firstSpace < 0) {
			fileIPFail(line); // error
		}

		String filename = fileAndIPLine.substring(0, firstSpace);
		String IP = fileAndIPLine.substring(firstSpace + 1);
		fileIPMap.put(filename, IP);
	}

	private void fileIPFail(String line) throws IOException {
		throw new IOException("Invalid Module.manifest entry for identifier \"" +
			MODULE_FILE_LICENSE + "\".\nThis line requires two parts: 1) " +
			"the module-relative file path and filename, and 2) the IP of " +
			"that file.\n  Found: " + line);
	}

	private void processNameLine(String line) {
		moduleName = line.substring(NAME_IDENTIFIER.length()).trim();
	}

	private void processFatJar(String line) {
		String fatJar = line.substring(FAT_JAR.length()).trim();
		fatJars.add(fatJar);
	}

	public String getModuleName() {
		return moduleName;
	}

	public Set<String> getDataSearchIgnoreDirs() {
		return dataSearchIgnoreDirs;
	}

	public Set<String> getFatJars() {
		return fatJars;
	}
}
