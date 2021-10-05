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
package ghidra.file.formats.android.bootldr;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "androidbootloader", description = "Android Boot Loader Image", factory = GFileSystemBaseFactory.class)
public class AndroidBootLoaderFileSystem extends GFileSystemBase {
	private List<GFileImpl> fileList = new ArrayList<>();
	private List<Integer> offsetList = new ArrayList<>();

	public AndroidBootLoaderFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, AndroidBootLoaderConstants.BOOTLDR_MAGIC_SIZE);
		return AndroidBootLoaderConstants.BOOTLDR_MAGIC.equals(new String(bytes).trim());
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true /*might not always be LE*/ );
		AndroidBootLoaderHeader header = new AndroidBootLoaderHeader(reader);
		int runningOffset = header.getStartOffset();
		for (AndroidBootLoaderImageInfo imageInfo : header.getImageInfoList()) {

			GFileImpl file = GFileImpl.fromFilename(this, root, imageInfo.getName(), false,
				imageInfo.getSize(), null);

			fileList.add(file);
			offsetList.add(runningOffset);

			runningOffset += imageInfo.getSize();
		}
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return new ArrayList<>(fileList);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		int index = fileList.indexOf(file);
		if (index < 0) {
			throw new IOException("Unknown file: " + file);
		}
		int offset = offsetList.get(index);
		return new ByteProviderWrapper(provider, offset, file.getLength(), file.getFSRL());
	}

}
