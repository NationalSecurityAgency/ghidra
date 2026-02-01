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

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link DebugFileProvider} that only looks in the program's original import directory for
 * matching debug files.
 */
public class SameDirDebugInfoProvider implements DebugFileProvider {

	public static final String DESC = "Program's Import Location";

	/**
	 * Returns true if the specified name string specifies a SameDirDebugInfoProvider.
	 *  
	 * @param name string to test
	 * @return boolean true if locString specifies a SameDirDebugInfoProvider
	 */
	public static boolean matches(String name) {
		return name.equals(".");
	}

	/**
	 * Creates a new {@link SameDirDebugInfoProvider} instance using the current program's
	 * import location.
	 * 
	 * @param name unused
	 * @param context {@link DebugInfoProviderCreatorContext} 
	 * @return new {@link SameDirDebugInfoProvider} instance
	 */
	public static SameDirDebugInfoProvider create(String name,
			DebugInfoProviderCreatorContext context) {
		File exeLocation = context.program() != null
				? new File(FilenameUtils.getFullPath(context.program().getExecutablePath()))
				: null;
		return new SameDirDebugInfoProvider(exeLocation);
	}

	private final File progDir;

	/**
	 * Creates a new {@link SameDirDebugInfoProvider} at the specified directory.
	 *  
	 * @param progDir path to the program's import directory
	 */
	public SameDirDebugInfoProvider(File progDir) {
		this.progDir = progDir;
	}

	@Override
	public String getName() {
		return ".";
	}

	@Override
	public String getDescriptiveName() {
		return DESC + (progDir != null ? " (" + progDir.getPath() + ")" : "");
	}

	@Override
	public DebugInfoProviderStatus getStatus(TaskMonitor monitor) {
		return progDir != null
				? progDir.isDirectory()
						? DebugInfoProviderStatus.VALID
						: DebugInfoProviderStatus.INVALID
				: DebugInfoProviderStatus.UNKNOWN;
	}

	@Override
	public File getFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (debugInfo.hasDebugLink()) {
			// This differs from the LocalDirDebugLinkProvider in that it does NOT recursively search
			// for the file
			File debugFile = new File(progDir, debugInfo.getFilename());
			if (debugFile.isFile()) {
				int fileCRC = LocalDirDebugLinkProvider.calcCRC(debugFile);
				if (fileCRC == debugInfo.getCrc()) {
					return debugFile; // success
				}
				Msg.info(this,
					"DWARF external debug file found with mismatching crc, ignored: %s, (%08x)"
							.formatted(debugFile, fileCRC));
			}
		}

		if (debugInfo.hasBuildId()) {
			// this probe is a w.a.g for what people might do when co-locating a build-id debug
			// file with the original binary
			File debugFile = new File(progDir, debugInfo.getBuildId() + ".debug");
			if (debugFile.isFile()) {
				return debugFile;
			}
		}

		return null;
	}

}
