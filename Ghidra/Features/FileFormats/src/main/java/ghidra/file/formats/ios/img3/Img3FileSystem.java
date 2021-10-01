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
package ghidra.file.formats.ios.img3;

import java.io.IOException;
import java.util.List;

import javax.swing.Icon;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.ios.img3.tag.DataTag;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "img3", description = "iOS " +
	Img3Constants.IMG3_SIGNATURE, factory = Img3FileSystemFactory.class)
public class Img3FileSystem implements GFileSystem {

	private FSRLRoot fsFSRL;
	private FileSystemRefManager fsRefManager = new FileSystemRefManager(this);
	private FileSystemIndexHelper<DataTag> fsIndexHelper;
	private ByteProvider provider;
	private FileSystemService fsService;

	public Img3FileSystem(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException {
		this.fsFSRL = fsFSRL;
		this.fsIndexHelper = new FileSystemIndexHelper<>(this, fsFSRL);
		this.provider = provider;
		this.fsService = fsService;

		monitor.setMessage("Opening IMG3...");
		Img3 header = new Img3(provider);
		if (!header.getMagic().equals(Img3Constants.IMG3_SIGNATURE)) {
			throw new IOException("Unable to decrypt file: invalid IMG3 file!");
		}
		List<DataTag> tags = header.getTags(DataTag.class);
		monitor.initialize(tags.size());

		for (int i = 0; i < tags.size(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(i);

			DataTag dataTag = tags.get(i);
			String filename = getDataTagFilename(dataTag, i, tags.size() > 1);
			fsIndexHelper.storeFileWithParent(filename, fsIndexHelper.getRootDir(), i, false,
				dataTag.getTotalLength(), dataTag);
		}
	}

	private String getDataTagFilename(DataTag dataTag, int index, boolean isMulti) {
		String filename = dataTag.getMagic();
		return isMulti ? (filename + index) : filename;
	}

	@Override
	public void close() throws IOException {
		fsRefManager.onClose();
		fsIndexHelper.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (fsFSRL.getNestingDepth() < 3) {
			throw new CryptoException(
				"Unable to decrypt IMG3 data because IMG3 crypto keys are specific to the container it is embedded in and this IMG3 was not in a container");
		}

		DataTag dataTag = fsIndexHelper.getMetadata(file);
		if (dataTag == null) {
			throw new IOException("Unknown file: " + file);
		}

		ByteProvider derivedBP = fsService.getDerivedByteProvider(fsFSRL.getContainer(),
			file.getFSRL(), "decrypted_img3_" + file.getName(), dataTag.getTotalLength(),
			() -> dataTag.getDecryptedInputStream(fsFSRL.getName(2), fsFSRL.getName(1)), monitor);

		return derivedBP;
	}

	public Icon getIcon() {
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		return fsIndexHelper.getListing(directory);
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
		return provider == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return fsRefManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

}
