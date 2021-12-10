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
package ghidra.file.formats.ubi;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.app.util.bin.format.ubi.FatArch;
import ghidra.app.util.bin.format.ubi.FatHeader;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.program.model.lang.Processor;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "universalbinary", description = "Mac OSX Universal Binary", factory = GFileSystemBaseFactory.class)
public class UniversalBinaryFileSystem extends GFileSystemBase {

	private FatHeader header;
	private List<GFileImpl> list = new ArrayList<>();

	public UniversalBinaryFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		int index = list.indexOf(file);
		FileAttributes result = new FileAttributes();
		if (index != -1) {
			result.add(FileAttributeType.COMMENT_ATTR,
				header.getArchitectures().get(index).toString());
		}
		return result;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return new ArrayList<>(list);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		boolean isLittleEndian = false;// always big endian
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);
		int magic = reader.readInt(0);
		int nArch = reader.readInt(4);
		if (magic == FatHeader.FAT_MAGIC || magic == FatHeader.FAT_CIGAM) {
			return nArch < 0x20;
		}
		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CancelledException {
		try {
			header = FatHeader.createFatHeader(RethrowContinuesFactory.INSTANCE, provider);
			List<FatArch> architectures = header.getArchitectures();
			for (FatArch architecture : architectures) {
				Processor processor =
					CpuTypes.getProcessor(architecture.getCpuType(), architecture.getCpuSubType());
				int bitSize = CpuTypes.getProcessorBitSize(architecture.getCpuType());
				String name = processor + "-" + bitSize + "-cpu0x" +
					Integer.toHexString(architecture.getCpuSubType());
				GFileImpl file =
					GFileImpl.fromFilename(this, root, name, false, architecture.getSize(), null);
				list.add(file);
			}
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		int index = list.indexOf(file);

		List<FatArch> architectures = header.getArchitectures();

		FatArch architecture = architectures.get(index);

		return new ByteProviderWrapper(provider, architecture.getOffset(), architecture.getSize(),
			file.getFSRL());
	}

	@Override
	public void close() throws IOException {
		super.close();
	}
}
