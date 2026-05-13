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
package ghidra.formats.gfilesystem;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class with common functionality for file systems that only contain a single file
 */
abstract public class AbstractSinglePayloadFileSystem implements GFileSystem {
	protected final FSRLRoot fsFSRL;
	protected final FileSystemRefManager refManager = new FileSystemRefManager(this);
	protected final SingleFileSystemIndexHelper fsIndex;
	protected ByteProvider payloadProvider;

	public AbstractSinglePayloadFileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider,
			String payloadFilename) {
		this(fsFSRL, payloadProvider, payloadFilename, FileAttributes.EMPTY);
	}

	public AbstractSinglePayloadFileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider,
			String payloadFilename, FileAttributes payloadAttrs) {
		this.fsFSRL = fsFSRL;
		this.payloadProvider = payloadProvider;
		String md5 = payloadProvider.getFSRL() != null ? payloadProvider.getFSRL().getMD5() : null;
		this.fsIndex = new SingleFileSystemIndexHelper(this, fsFSRL, payloadFilename,
			payloadProvider.length(), md5);
		this.fsIndex.setPayloadFileAttributes(payloadAttrs);
	}

	public GFile getPayloadFile() {
		return fsIndex.getPayloadFile();
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
		FSUtilities.uncheckedClose(payloadProvider, null);
		payloadProvider = null;
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
		return fsIndex.isClosed();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public int getFileCount() {
		return 1;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndex.lookup(path);
	}

	@Override
	public GFile lookup(String path, Comparator<String> nameComp) throws IOException {
		return fsIndex.lookup(null, path, nameComp);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fsIndex.isPayloadFile(file)) {
			return new ByteProviderWrapper(payloadProvider, file.getFSRL());
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndex.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		return fsIndex.getFileAttributes(file);
	}

}
