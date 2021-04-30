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
package ghidra.file.formats.complzss;

import java.io.*;
import java.util.List;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.lzss.LzssCodec;
import ghidra.file.formats.lzss.LzssConstants;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.HashUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "lzss", description = "LZSS Compression", factory = CompLzssFileSystemFactory.class)
public class CompLzssFileSystem implements GFileSystem {
	private FSRLRoot fsFSRL;
	private SingleFileSystemIndexHelper fsIndex;
	private FileSystemRefManager fsRefManager = new FileSystemRefManager(this);
	private ByteProvider payloadProvider;

	public CompLzssFileSystem(FSRLRoot fsrl, ByteProvider provider, TaskMonitor monitor)
			throws IOException {
		monitor.setMessage("Decompressing LZSS...");

		byte[] compressedBytes = provider.readBytes(LzssConstants.HEADER_LENGTH,
			provider.length() - LzssConstants.HEADER_LENGTH);
		ByteArrayOutputStream decompressedBOS = new ByteArrayOutputStream();
		LzssCodec.decompress(decompressedBOS, new ByteArrayInputStream(compressedBytes));
		byte[] decompressedBytes = decompressedBOS.toByteArray();

		String md5 = HashUtilities.getHash(HashUtilities.MD5_ALGORITHM, decompressedBytes);
		this.fsIndex = new SingleFileSystemIndexHelper(this, fsFSRL, "lzss_decompressed",
			decompressedBytes.length, md5);
		this.payloadProvider =
			new ByteArrayProvider(decompressedBytes, fsIndex.getPayloadFile().getFSRL());
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return fsRefManager;
	}

	@Override
	public boolean isClosed() {
		return payloadProvider == null;
	}

	@Override
	public void close() throws IOException {
		fsRefManager.onClose();
		if (payloadProvider != null) {
			payloadProvider.close();
			payloadProvider = null;
		}
		fsIndex.clear();
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ByteProvider bp = getByteProvider(file, monitor);
		return bp != null ? bp.getInputStream(0) : null;
	}

	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		return fsIndex.isPayloadFile(file) ? payloadProvider : null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndex.getListing(directory);
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndex.lookup(path);
	}

}
