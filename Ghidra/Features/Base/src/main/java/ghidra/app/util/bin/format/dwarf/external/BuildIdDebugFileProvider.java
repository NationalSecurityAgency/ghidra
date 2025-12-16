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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link DebugFileProvider} that expects the external debug files to be named using the hexadecimal
 * value of the hash of the file, and to be arranged in a bucketed directory hierarchy using the
 * first 2 hexdigits of the hash.
 * <p>
 * For example, the debug file with hash {@code 6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f} would
 * be stored as "6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug" (under some root directory). 
 */
public class BuildIdDebugFileProvider implements DebugFileProvider {
	private static final String BUILDID_NAME_PREFIX = "build-id://";

	/**
	 * Returns true if the specified name string specifies a BuildIdDebugFileProvider.
	 *  
	 * @param name string to test
	 * @return boolean true if name specifies a BuildIdDebugFileProvider
	 */
	public static boolean matches(String name) {
		return name.startsWith(BUILDID_NAME_PREFIX);
	}

	/**
	 * Creates a new {@link BuildIdDebugFileProvider} instance using the specified name string.
	 * 
	 * @param name string, earlier returned from {@link #getName()}
	 * @param context {@link DebugInfoProviderCreatorContext} to allow accessing information outside
	 * of the name string that might be needed to create a new instance
	 * @return new {@link BuildIdDebugFileProvider} instance
	 */
	public static BuildIdDebugFileProvider create(String name,
			DebugInfoProviderCreatorContext context) {
		name = name.substring(BUILDID_NAME_PREFIX.length());

		return new BuildIdDebugFileProvider(new File(name));
	}

	private final File rootDir;

	/**
	 * Creates a new {@link BuildIdDebugFileProvider} at the specified directory.
	 *  
	 * @param rootDir path to the root directory of the build-id directory (typically ends with
	 * "./build-id")
	 */
	public BuildIdDebugFileProvider(File rootDir) {
		this.rootDir = rootDir;
	}

	@Override
	public String getName() {
		return BUILDID_NAME_PREFIX + rootDir.getPath();
	}

	@Override
	public String getDescriptiveName() {
		return rootDir.getPath() + " (.build-id dir)";
	}

	@Override
	public DebugInfoProviderStatus getStatus(TaskMonitor monitor) {
		return rootDir.isDirectory()
				? DebugInfoProviderStatus.VALID
				: DebugInfoProviderStatus.INVALID;
	}

	@Override
	public File getFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		String buildId = debugInfo.getBuildId();
		if (buildId == null || buildId.length() < 4 /* 2 bytes = 4 hex digits */ ) {
			return null;
		}
		File bucketDir = new File(rootDir, buildId.substring(0, 2));
		File file = new File(bucketDir, buildId.substring(2) + ".debug");
		return file.isFile() ? file : null;
	}

}
