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
package ghidra.file.formats.cabarc;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.sevenzip.SevenZipCliToolWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.*;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CabarcFileSystemFactory
		implements GFileSystemFactoryByteProvider<CabarcFileSystem>, GFileSystemProbeBytesOnly {

	static final String CABARC_TMPFILE_PREFIX = "cabarc_tmp_";
	private static final byte[] CABARC_SIGNATURE_MAGIC =
		NumericUtilities.convertStringToBytes("4d53434600000000"); // "MSCF", 00000000

	private SevenZipCliToolWrapper cliTool;

	@Override
	public int getBytesRequired() {
		return CABARC_SIGNATURE_MAGIC.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return Arrays.equals(startBytes, 0, CABARC_SIGNATURE_MAGIC.length, CABARC_SIGNATURE_MAGIC,
			0, CABARC_SIGNATURE_MAGIC.length);
	}

	@Override
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		try {
			ensureTool(monitor);

			File archiveFile = fsService.getFileIfAvailable(byteProvider);
			File tmpFile = null;
			if (archiveFile == null) {
				archiveFile = tmpFile =
					fsService.createPlaintextTempFile(byteProvider, CABARC_TMPFILE_PREFIX, monitor);
			}

			CabarcFileSystem fs =
				new CabarcFileSystem(targetFSRL, fsService, cliTool, archiveFile, tmpFile);

			try {
				fs.mount(monitor);
				return fs;
			}
			catch (IOException e) {
				FSUtilities.uncheckedClose(fs, null);
				throw e;
			}
		}
		finally {
			FSUtilities.uncheckedClose(byteProvider, null);
		}
	}

	private void ensureTool(TaskMonitor monitor) throws IOException {
		if (cliTool == null) {
			cliTool = SevenZipCliToolWrapper.findTool(monitor);
		}
		if (cliTool == null) {
			throw new FileSystemFactoryDependencyException("No 7z cli tool found in PATH");
		}
	}

}
