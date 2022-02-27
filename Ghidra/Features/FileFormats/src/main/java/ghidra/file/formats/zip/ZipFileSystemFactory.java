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
package ghidra.file.formats.zip;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.sevenzip.SevenZipFileSystemFactory;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ZipFileSystemFactory
		implements GFileSystemFactoryByteProvider<ZipFileSystem>, GFileSystemProbeBytesOnly {
	/**
	 * Use "-Dghidra.file.formats.zip.ZipFileSystemFactory.USE_BUILTIN_ZIP_SUPPORT=true" jvm
	 * startup option to disable use of 7zip libraries when opening zip filesystems.
	 */
	private static boolean USE_BUILTIN_ZIP_SUPPORT = Boolean
			.getBoolean("ghidra.file.formats.zip.ZipFileSystemFactory.USE_BUILTIN_ZIP_SUPPORT");

	private static final int START_BYTES_REQUIRED = 2;

	/**
	 * Sets the static flag controlling which zip file implementation will used when opening
	 * a zip file system.
	 * 
	 * @param b boolean true forces use of the built-in java zip library (in other words, disables
	 * use of 7zip), false will allow the 7zip libraries to be attempted to be used
	 */
	public static void setUseBuiltinZipSupport(boolean b) {
		USE_BUILTIN_ZIP_SUPPORT = b;
	}

	@Override
	public int getBytesRequired() {
		return START_BYTES_REQUIRED;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return startBytes[0] == 'P' && startBytes[1] == 'K';
	}

	@Override
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		 
		// Try to use 7zip to handle .zip files, or fall back to using the less feature rich 
		// built-in java zip file support.
		if (!USE_BUILTIN_ZIP_SUPPORT && SevenZipFileSystemFactory.initNativeLibraries()) {
			ZipFileSystem fs = new ZipFileSystem(targetFSRL, fsService);
			try {
				fs.mount(byteProvider, monitor);
				return fs;
			}
			catch (IOException ioe) {
				fs.close();
				throw ioe;
			}
		}
		else {
			File zipFile = fsService.getFileIfAvailable(byteProvider);
			boolean deleteZipFileWhenDone = false;
			if (zipFile == null) {
				zipFile = fsService.createPlaintextTempFile(byteProvider,
					ZipFileSystemBuiltin.TEMPFILE_PREFIX, monitor);
				deleteZipFileWhenDone = true;
			}
			ZipFileSystemBuiltin fs = new ZipFileSystemBuiltin(targetFSRL, fsService);
			try {
				fs.mount(zipFile, deleteZipFileWhenDone, monitor);
				return fs;
			}
			catch (IOException ioe) {
				fs.close();
				throw ioe;
			}
		}
	}

}
