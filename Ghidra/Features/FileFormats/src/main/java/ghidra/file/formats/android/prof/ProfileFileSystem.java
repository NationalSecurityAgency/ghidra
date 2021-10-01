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
package ghidra.file.formats.android.prof;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.file.formats.zlib.ZLIB;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "prof", description = "PROF", factory = GFileSystemBaseFactory.class)
public class ProfileFileSystem extends GFileSystemBase {

	private ProfileHeader header;
	private GFileImpl dataFile;

	public ProfileFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true);
		header = new ProfileHeader(reader);
		dataFile = GFileImpl.fromFilename(this, root, "uncompressed-data", false,
			header.getUncompressedSizeOfZippedData(), null);
	}

	@Override
	public void close() throws IOException {
		super.close();
		header = null;
		dataFile = null;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (dataFile.equals(file)) {
			InputStream compressedStream =
				provider.getInputStream(header.getCompressedDataOffset());
			ZLIB zlib = new ZLIB();
			ByteArrayOutputStream decompressedBytes =
				zlib.decompress(compressedStream, header.getUncompressedSizeOfZippedData());
			return new ByteArrayProvider(decompressedBytes.toByteArray(), file.getFSRL());
		}
		return null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		if (file == dataFile) {
			return FileAttributes.of(FileAttribute.create("Magic", header.getMagic()));
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		List<GFile> list = new ArrayList<>();
		if (directory == null || directory.equals(root)) {
			list.add(dataFile);
		}
		return list;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		return ProfileConstants.isProfile(provider);
	}

}
