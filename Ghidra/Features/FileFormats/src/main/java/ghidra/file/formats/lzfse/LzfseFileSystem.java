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
package ghidra.file.formats.lzfse;

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystem} implementation LZFSE compressed files
 * 
 * @see <a href="https://github.com/lzfse/lzfse">lzfse reference implementation</a> 
 */
@FileSystemInfo(type = "lzfse", description = "LZFSE", factory = LzfseFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_HIGH)
public class LzfseFileSystem implements GFileSystem {

	private FSRLRoot fsFSRL;
	private SingleFileSystemIndexHelper fsIndex;
	private FileSystemRefManager fsRefManager = new FileSystemRefManager(this);
	private ByteProvider decompressedProvider;

	/**
	 * Creates a new {@link LzfseFileSystem}.
	 * <p>
	 * NOTE: Successful completion of this constructor will result in {@code decompressedFile}
	 * being deleted.
	 * 
	 * @param fsrlRoot This filesystem's {@link FSRLRoot}
	 * @param decompressedFile The decompressed lzfse {@link File file} (will be deleted after use)
	 * @param fsService The {@link FileSystemService}
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException If there was an IO-related error
	 * @throws CancelledException If the user cancelled the operation
	 */
	public LzfseFileSystem(FSRLRoot fsrlRoot, File decompressedFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Decompressing LZFSE...");

		this.fsFSRL = fsrlRoot;
		String name = "lzfse_decompressed";
		decompressedProvider =
			fsService.pushFileToCache(decompressedFile, fsFSRL.appendPath(name), monitor);
		fsIndex = new SingleFileSystemIndexHelper(this, fsFSRL, name,
			decompressedProvider.length(), decompressedProvider.getFSRL().getMD5());
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
		return decompressedProvider == null;
	}

	@Override
	public void close() throws IOException {
		fsRefManager.onClose();
		if (decompressedProvider != null) {
			decompressedProvider.close();
			decompressedProvider = null;
		}
		fsIndex.clear();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		return fsIndex.isPayloadFile(file)
				? new ByteProviderWrapper(decompressedProvider, file.getFSRL())
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
