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
package ghidra.file.formats.gzip;

import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryWithFile;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;

public class GZipFileSystemFactory
		implements GFileSystemFactoryWithFile<GZipFileSystem>, GFileSystemProbeBytesOnly {

	public static final int PROBE_BYTES_REQUIRED = GZipConstants.MAGIC_BYTES_COUNT;

	@Override
	public GZipFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
					throws IOException, CancelledException {

		GZipFileSystem fs =
			new GZipFileSystem(containerFSRL, targetFSRL, containerFile, fsService, monitor);
		return fs;
	}

	@Override
	public int getBytesRequired() {
		return PROBE_BYTES_REQUIRED;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return GZipUtil.isGZip(startBytes);
	}

}
