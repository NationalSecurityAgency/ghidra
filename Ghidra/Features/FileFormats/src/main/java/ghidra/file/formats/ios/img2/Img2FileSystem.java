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
package ghidra.file.formats.ios.img2;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@FileSystemInfo(
	type = "img2",
	description = "iOS " + Img2Constants.IMG2_SIGNATURE, 
	factory = Img2FileSystemFactory.class)
//@formatter:on
public class Img2FileSystem implements GFileSystem {

	private FSRLRoot fsFSRL;
	private SingleFileSystemIndexHelper fsIndexHelper;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private ByteProvider provider;
	private Img2 img2;

	public Img2FileSystem(FSRLRoot fsFSRL, ByteProvider provider, TaskMonitor monitor)
			throws IOException, CancelledException {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.img2 = new Img2(provider);
		if (!img2.isValid()) {
			throw new IOException("Unable to decrypt file: invalid IMG2 file!");
		}

		try (ByteProvider tmpBP =
			new ByteProviderWrapper(provider, Img2Constants.IMG2_LENGTH, img2.getDataLen(), null)) {
			String payloadMD5 = FSUtilities.getMD5(tmpBP, monitor);

			this.fsIndexHelper = new SingleFileSystemIndexHelper(this, fsFSRL, img2.getImageType(),
				img2.getDataLen(), payloadMD5);
		}
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndexHelper.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		if (fsIndexHelper.isPayloadFile(file)) {
			return new ByteProviderWrapper(provider, Img2Constants.IMG2_LENGTH, img2.getDataLen(),
				fsIndexHelper.getPayloadFile().getFSRL());
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndexHelper.getListing(directory);
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public boolean isClosed() {
		return fsIndexHelper.isClosed();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

}
