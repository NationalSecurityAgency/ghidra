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
package ghidra.file.formats.omf;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.omf.OmfFileHeader;
import ghidra.app.util.bin.format.omf.OmfLibraryRecord;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "omf", description = "OMF Archive", factory = OmfArchiveFileSystemFactory.class)
public class OmfArchiveFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<OmfLibraryRecord.MemberHeader> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	public OmfArchiveFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(TaskMonitor monitor) throws IOException {
		monitor.setMessage("Opening OMF archive...");
		BinaryReader reader = OmfFileHeader.createReader(provider);
		OmfLibraryRecord libraryRec = OmfLibraryRecord.parse(reader, monitor);
		ArrayList<OmfLibraryRecord.MemberHeader> memberHeaders = libraryRec.getMemberHeaders();
		for (OmfLibraryRecord.MemberHeader member : memberHeaders) {
			String name = member.name;
			monitor.setMessage(name);
			fsih.storeFile(name, fsih.getFileCount(), false, member.size, member);
		}
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
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
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
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		OmfLibraryRecord.MemberHeader member = fsih.getMetadata(file);
		return (member != null)
				? new ByteProviderWrapper(provider, member.payloadOffset, member.size,
					file.getFSRL())
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();

		OmfLibraryRecord.MemberHeader entry = fsih.getMetadata(file);
		if (entry != null) {
			result.add(NAME_ATTR, entry.name);
			result.add(SIZE_ATTR, entry.size);
		}
		return result;
	}

}
