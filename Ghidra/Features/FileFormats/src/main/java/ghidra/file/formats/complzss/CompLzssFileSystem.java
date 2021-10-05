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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.file.formats.lzss.LzssCodec;
import ghidra.file.formats.lzss.LzssConstants;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "lzss", description = "LZSS Compression", factory = CompLzssFileSystemFactory.class)
public class CompLzssFileSystem implements GFileSystem {
	private FSRLRoot fsFSRL;
	private SingleFileSystemIndexHelper fsIndex;
	private FileSystemRefManager fsRefManager = new FileSystemRefManager(this);
	private ByteProvider payloadProvider;

	public CompLzssFileSystem(FSRLRoot fsrl, ByteProvider provider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Decompressing LZSS...");

		try (ByteProvider tmpBP = new ByteProviderWrapper(provider, LzssConstants.HEADER_LENGTH,
			provider.length() - LzssConstants.HEADER_LENGTH);
				InputStream tmpIS = tmpBP.getInputStream(0);) {

			this.payloadProvider = fsService.getDerivedByteProviderPush(provider.getFSRL(), null,
				"decompressed lzss", -1, (os) -> LzssCodec.decompress(os, tmpIS), monitor);
			this.fsIndex = new SingleFileSystemIndexHelper(this, fsFSRL, "lzss_decompressed",
				payloadProvider.length(), payloadProvider.getFSRL().getMD5());
		}
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
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		return fsIndex.isPayloadFile(file)
				? new ByteProviderWrapper(payloadProvider, file.getFSRL())
				: null;
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
