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

import java.io.File;
import java.io.IOException;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link SearchLocation} that expects the external debug files to be named using the hexadecimal
 * value of the hash of the file, and to be arranged in a bucketed directory hierarchy using the
 * first 2 hexdigits of the hash.
 * <p>
 * For example, the debug file with hash {@code 6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f} would
 * be stored as "6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug" (under some root directory). 
 */
public class BuildIdSearchLocation implements SearchLocation {

	/**
	 * Returns true if the specified location string specifies a BuildIdSearchLocation.
	 *  
	 * @param locString string to test
	 * @return boolean true if locString specifies a BuildId location
	 */
	public static boolean isBuildIdSearchLocation(String locString) {
		return locString.startsWith(BUILD_ID_PREFIX);
	}

	/**
	 * Creates a new {@link BuildIdSearchLocation} instance using the specified location string.
	 * 
	 * @param locString string, earlier returned from {@link #getName()}
	 * @param context {@link SearchLocationCreatorContext} to allow accessing information outside
	 * of the location string that might be needed to create a new instance
	 * @return new {@link BuildIdSearchLocation} instance
	 */
	public static BuildIdSearchLocation create(String locString,
			SearchLocationCreatorContext context) {
		locString = locString.substring(BUILD_ID_PREFIX.length());

		return new BuildIdSearchLocation(new File(locString));
	}

	private static final String BUILD_ID_PREFIX = "build-id://";
	private final File rootDir;

	/**
	 * Creates a new {@link BuildIdSearchLocation} at the specified location.
	 *  
	 * @param rootDir path to the root directory of the build-id directory (typically ends with
	 * "./build-id")
	 */
	public BuildIdSearchLocation(File rootDir) {
		this.rootDir = rootDir;
	}

	@Override
	public String getName() {
		return BUILD_ID_PREFIX + rootDir.getPath();
	}

	@Override
	public String getDescriptiveName() {
		return rootDir.getPath() + " (build-id)";
	}

	@Override
	public FSRL findDebugFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		String hash = NumericUtilities.convertBytesToString(debugInfo.getHash());
		if (hash == null || hash.length() < 4 /* 2 bytes = 4 hex digits */ ) {
			return null;
		}
		File bucketDir = new File(rootDir, hash.substring(0, 2));
		File file = new File(bucketDir, hash.substring(2) + ".debug");
		return file.isFile() ? FileSystemService.getInstance().getLocalFSRL(file) : null;
	}

}
