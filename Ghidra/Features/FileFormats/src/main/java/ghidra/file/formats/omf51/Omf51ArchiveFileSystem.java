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
package ghidra.file.formats.omf51;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.omf.OmfException;
import ghidra.app.util.bin.format.omf.omf51.Omf51Library;
import ghidra.app.util.bin.format.omf.omf51.Omf51RecordFactory;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(
	type = "omf51",
	description = "OMF51 Library",
	factory = Omf51ArchiveFileSystemFactory.class
)
public class Omf51ArchiveFileSystem extends AbstractFileSystem<Omf51Library.MemberHeader> {

	private ByteProvider provider;

	public Omf51ArchiveFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		super(fsFSRL, FileSystemService.getInstance());
		this.provider = provider;
	}

	public void mount(TaskMonitor monitor) throws IOException, OmfException, CancelledException {
		monitor.setMessage("Opening OMF51 library...");
		Omf51RecordFactory factory = new Omf51RecordFactory(provider);
		List<Omf51Library.MemberHeader> members = new Omf51Library(factory).getMembers();

		monitor.initialize(members.size(), "Opening OMF51 library...");
		for (Omf51Library.MemberHeader member : members) {
			monitor.increment();
			fsIndex.storeFile(member.name(), fsIndex.getFileCount(), false, member.size(), member);
		}
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
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		Omf51Library.MemberHeader member = fsIndex.getMetadata(file);
		return (member != null)
				? new ByteProviderWrapper(provider, member.offset(), member.size(),
					file.getFSRL())
				: null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();

		Omf51Library.MemberHeader entry = fsIndex.getMetadata(file);
		if (entry != null) {
			result.add(NAME_ATTR, entry.name());
			result.add(SIZE_ATTR, entry.size());
		}
		return result;
	}
}
