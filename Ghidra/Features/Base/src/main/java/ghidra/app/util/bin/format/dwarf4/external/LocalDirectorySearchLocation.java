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
package ghidra.app.util.bin.format.dwarf4.external;

import java.io.*;
import java.util.zip.CRC32;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link SearchLocation} that recursively searches for dwarf external debug files 
 * under a configured directory. 
 */
public class LocalDirectorySearchLocation implements SearchLocation {

	private static final String LOCAL_DIR_PREFIX = "dir://";

	/**
	 * Returns true if the specified location string specifies a LocalDirectorySearchLocation.
	 *  
	 * @param locString string to test
	 * @return boolean true if locString specifies a local dir search location
	 */
	public static boolean isLocalDirSearchLoc(String locString) {
		return locString.startsWith(LOCAL_DIR_PREFIX);
	}

	/**
	 * Creates a new {@link LocalDirectorySearchLocation} instance using the specified location string.
	 * 
	 * @param locString string, earlier returned from {@link #getName()}
	 * @param context {@link SearchLocationCreatorContext} to allow accessing information outside
	 * of the location string that might be needed to create a new instance
	 * @return new {@link LocalDirectorySearchLocation} instance
	 */
	public static LocalDirectorySearchLocation create(String locString,
			SearchLocationCreatorContext context) {
		locString = locString.substring(LOCAL_DIR_PREFIX.length());
		return new LocalDirectorySearchLocation(new File(locString));
	}

	private final File searchDir;

	/**
	 * Creates a new {@link LocalDirectorySearchLocation} at the specified location.
	 *  
	 * @param searchDir path to the root directory of where to search
	 */
	public LocalDirectorySearchLocation(File searchDir) {
		this.searchDir = searchDir;
	}

	@Override
	public String getName() {
		return LOCAL_DIR_PREFIX + searchDir.getPath();
	}

	@Override
	public String getDescriptiveName() {
		return searchDir.getPath();
	}

	@Override
	public FSRL findDebugFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (!debugInfo.hasFilename()) {
			return null;
		}
		ensureSafeFilename(debugInfo.getFilename());
		return findFile(searchDir, debugInfo, monitor);
	}

	private void ensureSafeFilename(String filename) throws IOException {
		File testFile = new File(searchDir, filename);
		if (!searchDir.equals(testFile.getParentFile())) {
			throw new IOException("Unsupported path specified in debug file: " + filename);
		}
	}

	FSRL findFile(File dir, ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!debugInfo.hasFilename()) {
			return null;
		}
		File file = new File(dir, debugInfo.getFilename());
		if (file.isFile()) {
			int fileCRC = calcCRC(file);
			if (fileCRC == debugInfo.getCrc()) {
				return FileSystemService.getInstance().getLocalFSRL(file);
			}
			Msg.info(this, "DWARF external debug file found with mismatching crc, ignored: " +
				file + ", (" + Integer.toHexString(fileCRC) + ")");
		}
		File[] subDirs;
		if ((subDirs = dir.listFiles(f -> f.isDirectory())) != null) {
			for (File subDir : subDirs) {
				FSRL result = findFile(subDir, debugInfo, monitor);
				if (result != null) {
					return result;
				}
			}
		}
		return null;
	}

	/**
	 * Calculates the crc32 for the specified file.
	 * 
	 * @param f {@link File} to read
	 * @return int crc32
	 * @throws IOException if error reading file
	 */
	public static int calcCRC(File f) throws IOException {
		byte[] bytes = new byte[64 * 1024];

		CRC32 crc32 = new CRC32();
		int bytesRead;
		try (FileInputStream fis = new FileInputStream(f)) {
			while ((bytesRead = fis.read(bytes)) > 0) {
				crc32.update(bytes, 0, bytesRead);
			}
		}
		return (int) crc32.getValue();
	}

}
