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

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link SearchLocation} that only looks in the program's original import directory.  
 */
public class SameDirSearchLocation implements SearchLocation {

	/**
	 * Returns true if the specified location string specifies a SameDirSearchLocation.
	 *  
	 * @param locString string to test
	 * @return boolean true if locString specifies a BuildId location
	 */
	public static boolean isSameDirSearchLocation(String locString) {
		return locString.equals(".");
	}

	/**
	 * Creates a new {@link SameDirSearchLocation} instance using the current program's
	 * import location.
	 * 
	 * @param locString unused
	 * @param context {@link SearchLocationCreatorContext} 
	 * @return new {@link SameDirSearchLocation} instance
	 */
	public static SameDirSearchLocation create(String locString,
			SearchLocationCreatorContext context) {
		File exeLocation =
			new File(FilenameUtils.getFullPath(context.getProgram().getExecutablePath()));
		return new SameDirSearchLocation(exeLocation);
	}

	private final File progDir;

	/**
	 * Creates a new {@link SameDirSearchLocation} at the specified location.
	 *  
	 * @param progDir path to the program's import directory
	 */
	public SameDirSearchLocation(File progDir) {
		this.progDir = progDir;
	}

	@Override
	public String getName() {
		return ".";
	}

	@Override
	public String getDescriptiveName() {
		return progDir.getPath() + " (Program's Import Location)";
	}

	@Override
	public FSRL findDebugFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!debugInfo.hasFilename()) {
			return null;
		}
		File file = new File(progDir, debugInfo.getFilename());
		if (!file.isFile()) {
			return null;
		}
		int fileCRC = LocalDirectorySearchLocation.calcCRC(file);
		if (fileCRC != debugInfo.getCrc()) {
			Msg.info(this, "DWARF external debug file found with mismatching crc, ignored: " +
				file + ", (" + Integer.toHexString(fileCRC) + ")");
			return null;
		}
		return FileSystemService.getInstance().getLocalFSRL(file);
	}

}
