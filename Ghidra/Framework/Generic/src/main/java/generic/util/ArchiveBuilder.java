/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.util;

import ghidra.util.exception.AssertException;

import java.io.*;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ArchiveBuilder {

	private ZipOutputStream zipOut;

	ArchiveBuilder(ZipOutputStream zos) {
		this.zipOut = zos;
	}

	public void close() throws IOException {
		zipOut.close();
	}

	public void addFile(String path, File file) throws IOException {
		if (!file.isFile()) {
			throw new AssertException("Attempted to write a directory to the jar file");
		}

		long modifiedTime = file.lastModified();

		ZipEntry entry = new ZipEntry(path);
		entry.setTime(modifiedTime);

		zipOut.putNextEntry(entry);

		InputStream in = new FileInputStream(file);

		byte[] bytes = new byte[4096];
		int numRead;

		while ((numRead = in.read(bytes)) != -1) {
			zipOut.write(bytes, 0, numRead);
		}
		in.close();

		zipOut.closeEntry();

	}

	public void createFile(String path, List<String> lines) throws IOException {
		ZipEntry entry = new ZipEntry(path);

		zipOut.putNextEntry(entry);

		for (String line : lines) {
			zipOut.write(line.getBytes());
			zipOut.write('\n');
		}

		zipOut.closeEntry();
	}
}
