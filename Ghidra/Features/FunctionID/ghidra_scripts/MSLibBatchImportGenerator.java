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
// This script implements batch import operations of Microsoft .libs.
//
// After finding and categorizing the .libs as either 'standard' or 'debug', this
// script writes a control file per input .lib to the queue directory that instructs
// the MSLibBatchImportWorker script where and what to import.
//
// This script is meant to be run by the user in the normal Ghidra UI.
//
//@category FunctionID

import java.io.*;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;

public class MSLibBatchImportGenerator extends GhidraScript {

	long lastOneUp = -1;
	File outputDir;
	File outputNewDir;
	File outputTempDir;
	String pid;

	long getNextOneUp() {
		long next = System.currentTimeMillis();
		lastOneUp = Math.max(next, lastOneUp + 1);
		return lastOneUp;
	}

	File nextFile(File dir) throws IOException {
		long x = getNextOneUp();
		File f = new File(dir, Long.toHexString(x));
		if (f.exists()) {
			throw new IOException("File " + f + " already exists");
		}
		return f;
	}

	@Override
	protected void run() throws Exception {
		DomainFolder standardLibsDestRoot =
			askProjectFolder("Choose a top-level domain folder for STANDARD libraries");
		DomainFolder debugLibsDestRoot =
			askProjectFolder("Choose a top-level domain folder for DEBUG libraries");

		// ALL .LIB files under this directory will be inspected/imported as Win COFF
		File importSourceDir = askDirectory("Choose the top-level import directory", "Choose");

		outputDir = askDirectory("Choose the output queue directory", "Choose");
		outputNewDir = new File(outputDir, "new");
		outputNewDir.mkdir();
		outputTempDir = new File(outputDir, "tmp");
		outputTempDir.mkdir();

		List<File> standardLibs = new ArrayList<File>();
		List<File> debugLibs = new ArrayList<File>();

		processDirectory(standardLibs, debugLibs, importSourceDir);

		pid = getProcessId("fakepid_" + System.currentTimeMillis());

		for (File file : standardLibs) {
			String destFolder = getDestFolder(standardLibsDestRoot, importSourceDir, file);
			writeOutputFile(destFolder, file);
		}

		for (File file : debugLibs) {
			String destFolder = getDestFolder(debugLibsDestRoot, importSourceDir, file);
			writeOutputFile(destFolder, file);
		}

		println("Wrote " + standardLibs.size() + " standard files and " + debugLibs.size() +
			" debug file import txt files");
	}

	void writeOutputFile(String destFolder, File importFile) throws IOException {
		File f = nextFile(outputNewDir);
		File tmpFile = new File(outputTempDir, ".tmp_" + pid + "_" + f.getName());
		writeToFile(tmpFile, importFile.getPath() + "\n" + destFolder);
		if (!tmpFile.renameTo(f)) {
			throw new IOException("Failed to move " + tmpFile + " to " + f);
		}
	}

	public static void writeToFile(File file, String s) throws IOException {
		try (FileWriter writer = new FileWriter(file)) {
			writer.write(s);
		}
	}

	private static String getProcessId(String fallback) {
		// something like '<pid>@<hostname>', at least in SUN / Oracle JVMs
		String jvmName = ManagementFactory.getRuntimeMXBean().getName();
		int index = jvmName.indexOf('@');

		if (index > 0) {
			try {
				return Long.toString(Long.parseLong(jvmName.substring(0, index)));
			}
			catch (NumberFormatException e) {
				// ignore
			}
		}

		return fallback;
	}

	private static String getDestFolder(DomainFolder destRoot, File importRoot, File file) {
		String relativePath = getRelativePath(importRoot, file);
		String result = destRoot.getPathname();
		for (String s : relativePath.split("/")) {
			if (s.isEmpty()) {
				continue;
			}
			s = destRoot.getProjectData().makeValidName(s);
			if (!result.endsWith("/")) {
				result += "/";
			}
			result += s;
		}
		return result;
	}

	/**
	 * Recursively scans a directory for ".lib" files and adds them to either the
	 * non_debug_files list or the debug_files list.
	 * <p>
	 * Libraries are segregated into standard or debug versions by looking at the last character
	 * of the filename.  If it ends in 'd', and a base library with the same name minus the
	 * 'd' is in the directory, the library is determined to be a debug library.  All others
	 * are standard libraries.
	 * <p>   
	 * @param standardLibs
	 * @param debugLibs
	 * @param directory
	 */
	private void processDirectory(List<File> standardLibs, List<File> debugLibs, File directory) {

		File[] files = directory.listFiles();
		if (files == null) {
			return;
		}

		List<File> subdirs = new ArrayList<>();

		// filenames are forced into lower case before comparing because
		// MS windows filesystems are case-insensitive.
		Map<File, File> normalizedLibs = new HashMap<>();
		for (File file : files) {
			if (file.isFile() && getFileExt(file).toLowerCase().equals("lib")) {
				File normalizedFile = new File(directory, file.getName().toLowerCase());
				normalizedLibs.put(normalizedFile, file);
			}
			else if (file.isDirectory()) {
				subdirs.add(file);
			}
		}

		Set<File> localStdLibs = new HashSet<>();
		Set<File> localDebugLibs = new HashSet<>();
		for (Entry<File, File> entry : normalizedLibs.entrySet()) {
			File normalizedFile = entry.getKey();
			File libFile = entry.getValue();
			String libnameNoExt = getFilenameNoExt(normalizedFile);

			Set<File> destSet = localStdLibs;
			if (libnameNoExt.endsWith("d")) {
				String baseLibStr = libnameNoExt.substring(0, libnameNoExt.length() - 1) + ".lib";
				File baseLibFile = new File(normalizedFile.getParentFile(), baseLibStr);
				if (normalizedLibs.containsKey(baseLibFile)) {
					destSet = localDebugLibs;
				}
			}
			destSet.add(libFile);
		}
		standardLibs.addAll(localStdLibs);
		debugLibs.addAll(localDebugLibs);


		for (File subdir : subdirs) {
			processDirectory(standardLibs, debugLibs, subdir);
		}
	}

	/**
	 * Converts a file's path into forward-slash form.
	 * <p>
	 * @param f
	 * @return
	 */
	public static String getNormalizedFilePath(File f) {
		return f.getPath().replace('\\', '/');
	}

	public static String getNormalizedFilePath(String s) {
		return s.replace('\\', '/');
	}

	/**
	 * Returns the 'extension' of a 'filename.extension', or an empty string "" if not
	 * present.
	 * <p> 
	 * <li>"file.ext" returns "ext"
	 * <li>"file" returns ""
	 * @param f
	 * @return
	 */
	public static String getFileExt(File f) {
		String s = f.getName();
		int cp = s.lastIndexOf('.');
		return cp >= 0 ? s.substring(cp + 1) : "";
	}

	public static String getFilenameNoExt(File f) {
		String s = f.getName();
		int cp = s.lastIndexOf('.');
		return cp < 0 ? s : s.substring(0, cp);
	}

	/**
	 * Returns a string that represents the relative path (normalized to forward slashes)
	 * from the {@code base} path to the {@code sub} path.  
	 * 
	 * If {@code sub} is not really a subpath of {@code base}, the full path to {@code sub} will be returned.
	 * <p>
	 * <li>"/dir1", "/dir1/sub1/sub2" returns "sub1/sub2".
	 * <li>"/", "/sub1/sub2" returns "sub1/sub2".
	 * <li>"/dir1", "/dir2/sub1" returns "/dir2/sub1".
	 * <li>"c:\\dir1", "c:\\dir1\\sub1\\sub2" returns "sub1/sub2". 
	 * 
	 * @param base
	 * @param sub
	 * @return
	 */
	public static String getRelativePath(File base, File sub) {
		String baseStr = getNormalizedFilePath(base);
		if (!baseStr.endsWith("/")) {
			baseStr = baseStr + "/";
		}
		String subStr = getNormalizedFilePath(sub);
		return subStr.startsWith(baseStr) ? subStr.substring(baseStr.length()) : subStr;
	}

}
