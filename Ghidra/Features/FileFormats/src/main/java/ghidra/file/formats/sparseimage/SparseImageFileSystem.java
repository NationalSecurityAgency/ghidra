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
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A pseudo filesystem that contains a single file that is the decompressed contents
 * of the sparse container file.
 */
@FileSystemInfo(type = "simg", description = "Android Sparse Image (simg)", factory = SparseImageFileSystemFactory.class)
public class SparseImageFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private final FileSystemService fsService;

	private ByteProvider byteProvider;
	private ByteProvider payloadProvider;
	private SingleFileSystemIndexHelper fsIndexHelper;

	public SparseImageFileSystem(FSRLRoot fsFSRL, ByteProvider byteProvider,
			FileSystemService fsService,
			TaskMonitor monitor) throws CancelledException, IOException {
		this.fsFSRL = fsFSRL;
		this.fsService = fsService;
		this.byteProvider = byteProvider;

		this.payloadProvider = getPayload(null, monitor);
		FSRL containerFSRL = byteProvider.getFSRL();
		String payloadName = containerFSRL.getName() + ".raw";
		this.fsIndexHelper = new SingleFileSystemIndexHelper(this, fsFSRL, payloadName,
			payloadProvider.length(), payloadProvider.getFSRL().getMD5());
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndexHelper.clear();
		if (byteProvider != null) {
			byteProvider.close();
			byteProvider = null;
		}
		if (payloadProvider != null) {
			payloadProvider.close();
			payloadProvider = null;
		}
	}

	@Override
	public boolean isClosed() {
		return fsIndexHelper.isClosed();
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
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

	private ByteProvider getPayload(FSRL payloadFSRL, TaskMonitor monitor)
			throws CancelledException, IOException {
		return fsService.getDerivedByteProviderPush(byteProvider.getFSRL(), payloadFSRL, "sparse",
			-1, os -> {
				SparseImageDecompressor sid = new SparseImageDecompressor(byteProvider, os);
				sid.decompress(monitor);
			}, monitor);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fsIndexHelper.isPayloadFile(file)) {
			return new ByteProviderWrapper(payloadProvider, file.getFSRL());
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndexHelper.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		if (fsIndexHelper.isPayloadFile(file)) {
			try {
				result.add(SIZE_ATTR, payloadProvider.length());
				result.add(COMPRESSED_SIZE_ATTR, byteProvider.length());
			}
			catch (IOException e) {
				// ignore and continue
			}
			result.add("MD5", fsIndexHelper.getPayloadFile().getFSRL().getMD5());
		}
		return result;
	}
}
