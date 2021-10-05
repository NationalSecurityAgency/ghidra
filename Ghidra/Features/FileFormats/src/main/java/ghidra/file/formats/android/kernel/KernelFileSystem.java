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
package ghidra.file.formats.android.kernel;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "androidkernel", description = "Android Compressed Kernel", factory = GFileSystemBaseFactory.class)
public class KernelFileSystem extends GFileSystemBase {

	private static final int INDEX_WHERE_TO_START = 0x2000;//where to start looking for compressed kernel

	private GFile compressedKernelFile = null;
	private long compressedKernelIndex;
	private long compressedKernelLength;

	public KernelFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, 0x20);
		for (int i = 0; i < bytes.length; i += 4) {
			if (bytes[i] == (byte) 0x00 && bytes[i + 1] == (byte) 0x00 &&
				bytes[i + 2] == (byte) 0xa0 && bytes[i + 3] == (byte) 0xe1) {
				continue;
			}
			return false;
		}
		return true;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {

		// Scan through the file looking for the message below.
		// The next byte after the message should be the compressed kernel

		final String message = "uncompression error";

		int index = INDEX_WHERE_TO_START;

		monitor.setMaximum(provider.length());

		while (index < provider.length() - message.length() + 1) {
			monitor.checkCanceled();
			monitor.setProgress(index);

			String actualMessage = new String(provider.readBytes(index, message.length()));

			if (message.equals(actualMessage)) {// immediately following this string is the compressed pay-load....

				compressedKernelIndex =
					(index & 0xffffffffL) + (message.length() & 0xffffffffL) + 1;

				compressedKernelLength = provider.length() - compressedKernelIndex;

				compressedKernelFile = GFileImpl.fromFilename(this, root, "compressed-kernel",
					false, compressedKernelLength, null);

				break;
			}

			++index;
		}
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) && (compressedKernelFile != null)
				? Arrays.asList(compressedKernelFile)
				: Collections.emptyList();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (compressedKernelFile != null && compressedKernelFile.equals(file)) {
			return new ByteProviderWrapper(provider, compressedKernelIndex,
				provider.length() - compressedKernelIndex, file.getFSRL());
		}
		return null;
	}

}
