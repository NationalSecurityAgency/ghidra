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
package ghidra.file.formats.bzip2;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;

import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.tukaani.xz.XZ;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class XzFileSystemFactory
		implements GFileSystemFactoryByteProvider<XzFileSystem>, GFileSystemProbeBytesOnly {

	@Override
	public XzFileSystem create(FSRLRoot targetFSRL, ByteProvider provider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		String containerName = targetFSRL.getContainer().getName();
		String payloadFilename = containerName.endsWith(".xz")
				? containerName.substring(0, containerName.length() - ".xz".length())
				: containerName + ".uncompressed";

		ByteProvider payloadProvider =
			fsService.getDerivedByteProvider(provider.getFSRL(), null, payloadFilename, -1,
				() -> new XZCompressorInputStream(provider.getInputStream(0)), monitor);

		FileAttributes fileAttrs = FileAttributes.of( // attrs
			FileAttribute.create(COMPRESSED_SIZE_ATTR, provider.length()),
			FileAttribute.create(SIZE_ATTR, payloadProvider.length()));

		XzFileSystem fs = new XzFileSystem(targetFSRL, payloadProvider, payloadFilename, fileAttrs);

		return fs;
	}

	@Override
	public int getBytesRequired() {
		return XZ.HEADER_MAGIC.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return XZCompressorInputStream.matches(startBytes, startBytes.length);
	}
}
