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
package ghidra.app.util.bin.format.dwarf.external;

import java.io.*;
import java.util.zip.CRC32;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Searches for DWARF external debug files specified via a debug-link filename / crc in a directory.
 */
public class LocalDirDebugLinkProvider implements DebugFileProvider {

	private static final String DEBUGLINK_NAME_PREFIX = "debuglink://";

	/**
	 * Returns true if the specified name string specifies a LocalDirDebugLinkProvider.
	 *  
	 * @param name string to test
	 * @return boolean true if name specifies a LocalDirDebugLinkProvider name
	 */
	public static boolean matches(String name) {
		return name.startsWith(DEBUGLINK_NAME_PREFIX);
	}

	/**
	 * Creates a new {@link LocalDirDebugLinkProvider} instance using the specified name string.
	 * 
	 * @param name string, earlier returned from {@link #getName()}
	 * @param context {@link DebugInfoProviderCreatorContext} to allow accessing information outside
	 * of the name string that might be needed to create a new instance
	 * @return new {@link LocalDirDebugLinkProvider} instance
	 */
	public static LocalDirDebugLinkProvider create(String name,
			DebugInfoProviderCreatorContext context) {
		String dir = name.substring(DEBUGLINK_NAME_PREFIX.length());
		return new LocalDirDebugLinkProvider(new File(dir));
	}

	private final File searchDir;

	/**
	 * Creates a new {@link LocalDirDebugLinkProvider} at the specified dir.
	 *  
	 * @param searchDir path to the root directory of where to search
	 */
	public LocalDirDebugLinkProvider(File searchDir) {
		this.searchDir = searchDir;
	}

	@Override
	public String getName() {
		return DEBUGLINK_NAME_PREFIX + searchDir.getPath();
	}

	@Override
	public String getDescriptiveName() {
		return searchDir.getPath() + " (debug-link dir)";
	}

	@Override
	public DebugInfoProviderStatus getStatus(TaskMonitor monitor) {
		return isValid()
				? DebugInfoProviderStatus.VALID
				: DebugInfoProviderStatus.INVALID;
	}

	private boolean isValid() {
		return searchDir.isDirectory();
	}

	@Override
	public File getFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (!debugInfo.hasDebugLink() || !isValid()) {
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

	File findFile(File dir, ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!debugInfo.hasDebugLink()) {
			return null;
		}
		File file = new File(dir, debugInfo.getFilename());
		if (file.isFile()) {
			int fileCRC = calcCRC(file);
			if (fileCRC == debugInfo.getCrc()) {
				return file; // success
			}
			Msg.info(this,
				"DWARF external debug file found with mismatching crc, ignored: %s (%08x)"
						.formatted(file, fileCRC));
		}
		File[] subDirs;
		if ((subDirs = dir.listFiles(f -> f.isDirectory())) != null) {
			// TODO: prevent recursing into symlinks?
			for (File subDir : subDirs) {
				File result = findFile(subDir, debugInfo, monitor);
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
