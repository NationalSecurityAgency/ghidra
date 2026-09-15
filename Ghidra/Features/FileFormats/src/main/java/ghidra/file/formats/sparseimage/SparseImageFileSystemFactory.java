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
package ghidra.file.formats.sparseimage;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SparseImageFileSystemFactory implements
		GFileSystemFactoryByteProvider<SparseImageFileSystem>, GFileSystemProbeByteProvider {

	@Override
	public SparseImageFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			ByteProvider payloadProvider = fsService
					.getDerivedByteProviderPush(byteProvider.getFSRL(), null, "sparse", -1, os -> {
						SparseImageDecompressor sid = new SparseImageDecompressor(byteProvider, os);
						sid.decompress(monitor);
					}, monitor);

			FileAttributes payloadAttrs = FileAttributes.of( // attrs
				FileAttribute.create(SIZE_ATTR, payloadProvider.length()),
				FileAttribute.create(COMPRESSED_SIZE_ATTR, byteProvider.length()));

			String payloadName = targetFSRL.getContainer().getName() + ".raw";

			return new SparseImageFileSystem(targetFSRL, payloadProvider, payloadName,
				payloadAttrs);
		}
		finally {
			FSUtilities.uncheckedClose(byteProvider, null);
		}
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor taskMonitor) throws IOException, CancelledException {

		BinaryReader reader = new BinaryReader(byteProvider, true);
		SparseHeader header = new SparseHeader(reader);
		return header.getMagic() == SparseConstants.SPARSE_HEADER_MAGIC;

	}

}
