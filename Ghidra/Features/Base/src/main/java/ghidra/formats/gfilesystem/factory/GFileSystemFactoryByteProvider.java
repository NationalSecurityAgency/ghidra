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
package ghidra.formats.gfilesystem.factory;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystemFactory} interface for filesystem implementations
 * that use a {@link ByteProvider}.
 * 
 * @param <FSTYPE>
 */
public interface GFileSystemFactoryByteProvider<FSTYPE extends GFileSystem>
		extends GFileSystemFactory<FSTYPE> {

	/**
	 * Constructs a new {@link GFileSystem} instance that handles the specified file.
	 * 
	 * @param targetFSRL the {@link FSRLRoot} of the filesystem being created.
	 * @param byteProvider a {@link ByteProvider} containing the contents of the file being probed.
	 * This method is responsible for closing this byte provider instance.
	 * @param fsService a reference to the {@link FileSystemService} object
	 * @param monitor a {@link TaskMonitor} that should be polled to see if the user has
	 * requested to cancel the operation, and updated with progress information.
	 * @return a new {@link GFileSystem} derived instance.
	 * @throws IOException if there is an error reading files.
	 * @throws CancelledException if the user cancels
	 */
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException;
}
