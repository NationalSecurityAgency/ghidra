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

import java.io.*;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.generic.auth.Password;
import ghidra.util.task.TaskMonitor;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;

/**
 * Wrapper around zip4j's ZipFile impl, mainly used to access password protected entries in a
 * zip file.
 * <p>
 * If the supplied ByteProvider isn't a simple wrapper around a real local file, the contents of
 * the ByteProvider will be written out to a temp file for the duration of this object so that
 * zip4j can access it.
 */
public class Zip4jFileHandler implements Closeable {
	private static final String ZIP_TEMPFILE_PREFIX = "ghidra_tmp_zip";

	private ZipFile zipFile;
	private List<FileHeader> zipEntries;

	private File file;
	private File tmpZipFile;
	private boolean deleteZipFileWhenDone;

	public Zip4jFileHandler(ByteProvider bp, FileSystemService fsService, TaskMonitor monitor)
			throws IOException {

		file = fsService.getFileIfAvailable(bp);
		if (file == null) {
			tmpZipFile = file = fsService.createPlaintextTempFile(bp, ZIP_TEMPFILE_PREFIX, monitor);
			deleteZipFileWhenDone = true;
		}

		this.zipFile = new ZipFile(file);
		this.zipEntries = zipFile.getFileHeaders();
	}

	@Override
	public void close() throws IOException {
		if (zipFile != null) {
			zipFile.close();
			zipFile = null;
		}
		if (tmpZipFile != null && deleteZipFileWhenDone) {
			tmpZipFile.delete();
			tmpZipFile = null;
		}
	}

	public InputStream getInputStream(int fileIndex, Password password) throws IOException {
		zipFile.setPassword(password.getPasswordChars());
		return zipFile.getInputStream(zipEntries.get(fileIndex));
	}

}
