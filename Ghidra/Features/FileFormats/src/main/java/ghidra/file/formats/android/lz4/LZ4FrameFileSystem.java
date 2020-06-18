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
package ghidra.file.formats.android.lz4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileImpl;
import ghidra.formats.gfilesystem.GFileSystemBase;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * See: https://android.googlesource.com/platform/external/lz4/+/HEAD/doc/lz4_Frame_format.md
 *
 */
@FileSystemInfo(type = "lz4frame", description = "LZ4 Frame Format", factory = GFileSystemBaseFactory.class)
public class LZ4FrameFileSystem extends GFileSystemBase {

	/** LZ4 Magic Number */
	public final static int LZ4F_MAGIC = 0x184D2204;
	public final static byte[] LZ4F_MAGIC_BYTES = { 0x04, 0x22, 0x4d, 0x18 };

	public final static String NAME = "lz4f_decompressed";

	private GFile decompressedLZ4FFile = null;

	public LZ4FrameFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, LZ4F_MAGIC_BYTES.length);
		return Arrays.equals(bytes, LZ4F_MAGIC_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CancelledException {
		byte[] decompressedBytes = decompress(monitor);
		decompressedLZ4FFile =
			GFileImpl.fromFilename(this, root, NAME, false, decompressedBytes.length, null);
	}

	private byte[] decompress(TaskMonitor monitor) throws IOException {
		monitor.setShowProgressValue(true);
		monitor.setMaximum(100000);
		monitor.setProgress(0);
		monitor.setMessage("Decompressing LZ4 Frame...");
		FramedLZ4CompressorInputStream lz4 =
			new FramedLZ4CompressorInputStream(provider.getInputStream(0));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int chunk = 0;
		while (!monitor.isCancelled()) {
			byte[] bytes = new byte[0x1000];
			int nRead = lz4.read(bytes);
			if (nRead <= 0) {
				break;
			}
			++chunk;
			monitor.incrementProgress(1);
			monitor.setMessage(
				"Decompressing LZ4F ... " + chunk + " ... 0x" + Integer.toHexString(nRead));
			baos.write(bytes, 0, nRead);
		}
		lz4.close();
		return baos.toByteArray();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (file == decompressedLZ4FFile || file.equals(decompressedLZ4FFile)) {
			byte[] decompressedBytes = decompress(monitor);
			return new ByteArrayInputStream(decompressedBytes);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) && (decompressedLZ4FFile != null)
				? Arrays.asList(decompressedLZ4FFile)
				: Collections.emptyList();
	}
}
