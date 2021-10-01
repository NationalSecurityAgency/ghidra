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
import java.util.List;

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
public class CoffArchiveFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<CoffArchiveMemberHeader> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	public CoffArchiveFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(TaskMonitor monitor) throws IOException {

		try {
			monitor.setMessage("Opening COFF archive...");
			CoffArchiveHeader caf = CoffArchiveHeader.read(provider, monitor);
			for (CoffArchiveMemberHeader camh : caf.getArchiveMemberHeaders()) {
				if (camh.isCOFF()) {
					String name = camh.getName().replace('\\', '/');//replace stupid windows backslashes.
					monitor.setMessage(name);

					fsih.storeFile(name, fsih.getFileCount(), false, camh.getSize(), camh);
				}
			}
		}
		catch (CoffException e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		CoffArchiveMemberHeader entry = fsih.getMetadata(file);
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
		fsih.clear();
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		CoffArchiveMemberHeader entry = fsih.getMetadata(file);
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

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}
