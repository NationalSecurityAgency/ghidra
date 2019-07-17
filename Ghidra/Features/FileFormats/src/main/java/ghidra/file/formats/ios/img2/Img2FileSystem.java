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

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "img2", description = "iOS " +
	Img2Constants.IMG2_SIGNATURE, factory = GFileSystemBaseFactory.class)
public class Img2FileSystem extends GFileSystemBase {

	private Img2 img2;
	private GFileImpl imageTypeFile;

	public Img2FileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		super.close();
		imageTypeFile = null;
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		if (file != null && file.equals(imageTypeFile)) {

			byte[] data = provider.readBytes(Img2Constants.IMG2_LENGTH, img2.getDataLen());

			return new ByteArrayInputStream(data);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) ? Arrays.asList(imageTypeFile)
				: Collections.emptyList();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, Img2Constants.IMG2_SIGNATURE_BYTES.length);
		return Arrays.equals(bytes, Img2Constants.IMG2_SIGNATURE_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Opening IMG2...");

		this.img2 = new Img2(provider);

		if (!img2.getSignature().equals(Img2Constants.IMG2_SIGNATURE)) {
			throw new IOException("Unable to decrypt file: invalid IMG2 file!");
		}

		imageTypeFile =
			GFileImpl.fromFilename(this, root, img2.getImageType(), false, img2.getDataLen(), null);
	}

}
