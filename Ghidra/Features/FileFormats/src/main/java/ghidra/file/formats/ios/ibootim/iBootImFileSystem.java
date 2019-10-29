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
package ghidra.file.formats.ios.ibootim;

import java.io.*;
import java.util.*;

import javax.swing.Icon;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.lzss.LzssCodec;
import ghidra.file.image.GImage;
import ghidra.file.image.GImageFormat;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "ibootim", description = "iOS " +
	iBootImConstants.SIGNATURE, factory = GFileSystemBaseFactory.class)
public class iBootImFileSystem extends GFileSystemBase implements GIconProvider {

	private iBootImHeader header;
	private List<GFile> fileList = new ArrayList<>();
	private byte[] bytes = new byte[0];

	public iBootImFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		bytes = new byte[0];
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		return new ByteArrayInputStream(bytes);
	}

	@Override
	public Icon getIcon(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
		File cacheFile = fsService.getFile(file.getFSRL(), monitor);
		try (InputStream cacheInputStream = new FileInputStream(cacheFile)) {
			GImageFormat format =
				(header.getFormat() == iBootImConstants.FORMAT_ARGB) ? GImageFormat.RGB_ALPHA_4BYTE
						: GImageFormat.GRAY_ALPHA_2BYTE;
			GImage image = new GImage(header.getWidth(), header.getHeight(), format,
				cacheInputStream, cacheFile.length());
			return image.toPNG();
		}
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			return fileList;
		}
		return new ArrayList<>();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, iBootImConstants.SIGNATURE_LENGTH);
		return Arrays.equals(bytes, iBootImConstants.SIGNATURE_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Opening iBoot Image...");

		this.header = new iBootImHeader(provider);

		byte[] compressedBytes = provider.readBytes(iBootImConstants.HEADER_LENGTH,
			provider.length() - iBootImConstants.HEADER_LENGTH);
		ByteArrayOutputStream decompressedBytes = new ByteArrayOutputStream();
		LzssCodec.decompress(decompressedBytes, new ByteArrayInputStream(compressedBytes));
		bytes = decompressedBytes.toByteArray();

		String name = StringUtilities.toString(header.getFormat()) + "_image";

		GFileImpl file =
			GFileImpl.fromFilename(this, root, name, false, decompressedBytes.size(), null);

		fileList.add(file);
	}

}
