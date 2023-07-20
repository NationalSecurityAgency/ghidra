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
package ghidra.file.formats.coff;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.Date;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.coff.CoffException;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "coff", description = "COFF Archive", factory = CoffArchiveFileSystemFactory.class)
public class CoffArchiveFileSystem extends AbstractFileSystem<CoffArchiveMemberHeader> {

	private ByteProvider provider;

	public CoffArchiveFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		super(fsFSRL, FileSystemService.getInstance());
		this.provider = provider;
	}

	public void mount(TaskMonitor monitor) throws IOException {

		try {
			monitor.setMessage("Opening COFF archive...");
			CoffArchiveHeader caf = CoffArchiveHeader.read(provider, monitor);
			for (CoffArchiveMemberHeader camh : caf.getArchiveMemberHeaders()) {
				if (camh.isCOFF()) {
					String name = camh.getName().replace('\\', '/');//replace stupid windows backslashes.
					monitor.setMessage(name);

					fsIndex.storeFile(name, fsIndex.getFileCount(), false, camh.getSize(), camh);
				}
			}
		}
		catch (CoffException e) {
			throw new IOException(e);
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		CoffArchiveMemberHeader entry = fsIndex.getMetadata(file);
		return (entry != null && entry.isCOFF())
				? new ByteProviderWrapper(provider, entry.getPayloadOffset(), entry.getSize(),
					file.getFSRL())
				: null;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsIndex.clear();
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		CoffArchiveMemberHeader entry = fsIndex.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (entry != null) {
			result.add(NAME_ATTR, entry.getName());
			result.add(SIZE_ATTR, entry.getSize());
			result.add(USER_ID_ATTR, (long) entry.getUserIdInt());
			result.add(GROUP_ID_ATTR, (long) entry.getGroupIdInt());
			result.add(MODIFIED_DATE_ATTR, new Date(entry.getDate()));
			result.add("Mode", entry.getMode());
		}
		return result;
	}
}
