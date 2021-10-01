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
package ghidra.file.formats.ios.apple8900;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.crypto.DecryptedPacket;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "apple8900", description = "Apple 8900", factory = GFileSystemBaseFactory.class)
public class Apple8900FileSystem extends GFileSystemBase {

	private GFileImpl dataFile;

	public Apple8900FileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		dataFile = null;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		if (file != null && file.equals(dataFile)) {
			return fsService.getDerivedByteProvider(provider.getFSRL(), file.getFSRL(),
				file.getName(), -1, () -> {
					Apple8900Decryptor decryptor = new Apple8900Decryptor();
					DecryptedPacket decrypt = decryptor.decrypt(null /* does not matter*/,
						null /* does not matter */, provider, monitor);
					return decrypt.decryptedStream;
				}, monitor);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		List<GFile> tmp = new ArrayList<>();
		if (directory == null || directory.equals(root)) {
			tmp.add(dataFile);
		}
		return tmp;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] magic = provider.readBytes(0, Apple8900Constants.MAGIC_LENGTH);
		return Arrays.equals(magic, Apple8900Constants.MAGIC_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {

		Apple8900Header header = new Apple8900Header(provider);

		if (!header.getMagic().equals(Apple8900Constants.MAGIC)) {
			throw new IOException("Unable to decrypt file: invalid Apple 8900 file!");
		}

		dataFile = GFileImpl.fromFilename(this, root, "DATA", false, header.getSizeOfData(), null);

	}
}
