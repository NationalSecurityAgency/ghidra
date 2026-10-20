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
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.cliwrapper.ArchiverCliToolWrapper.Entry;
import ghidra.file.formats.sevenzip.SevenZipCliToolWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
* File system that handles Microsoft CAB archive files (including compressed symbol server files).
* <p>
* Requires the user having installed a command-line 7z tool somewhere in their PATH.
* <p>
* If the container file isn't a plain file, the container will be exported to a temp file so that
* the 7z cli tool can access it. 
*/
//@formatter:off
@FileSystemInfo(
	type = "cabarc",
	description = "Microsoft CAB Archive",
	factory = CabarcFileSystemFactory.class,
	extensions = { "cab" }
)
//@formatter:on
public class CabarcFileSystem extends AbstractFileSystem<Entry> {
	private SevenZipCliToolWrapper cliTool;

	private File archiveFile;
	private File tmpFile;

	public CabarcFileSystem(FSRLRoot fsrl, FileSystemService fsService,
			SevenZipCliToolWrapper cliTool, File archiveFile, File tmpFile) {
		super(fsrl, fsService);

		this.cliTool = cliTool;
		this.archiveFile = archiveFile;
		this.tmpFile = tmpFile;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();

		if (tmpFile != null &&
			tmpFile.getName().startsWith(CabarcFileSystemFactory.CABARC_TMPFILE_PREFIX)) {
			tmpFile.delete();
			tmpFile = null;
		}
		archiveFile = null;

		fsIndex.clear();
	}

	public void mount(TaskMonitor monitor) throws IOException {
		if (!cliTool.isValid(monitor)) {
			throw new IOException("Bad cli tool");
		}
		List<Entry> listing = cliTool.getListing(archiveFile, monitor);
		int fileIndex = 0;
		for (Entry entry : listing) {
			fsIndex.storeFile(entry.name(), fileIndex++, entry.fileType() == FileType.DIRECTORY,
				entry.size(), entry);
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		GFile resolvedFile = fsIndex.resolveSymlinks(file); // probably not needed with sz

		Entry entry = fsIndex.getMetadata(resolvedFile);
		if (entry == null) {
			throw new IOException("Unknown file " + file);
		}

		ByteProvider fileBP = fsService.getDerivedByteProviderPush(fsFSRL.getContainer(), null,
			file.getPath(), -1, (os) -> cliTool.extract(archiveFile, entry, os, monitor), monitor);

		return fileBP;
	}

	@Override
	public boolean isClosed() {
		return archiveFile == null;
	}

}
