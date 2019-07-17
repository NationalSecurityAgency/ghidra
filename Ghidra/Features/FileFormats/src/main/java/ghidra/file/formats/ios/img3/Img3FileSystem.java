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

import java.io.*;
import java.util.*;

import javax.swing.Icon;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.ios.img3.tag.DataTag;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "img3", description = "iOS " +
	Img3Constants.IMG3_SIGNATURE, factory = GFileSystemBaseFactory.class)
public class Img3FileSystem extends GFileSystemBase {

	private Img3 header;
	private List<GFile> dataFileList = new ArrayList<>();

	public Img3FileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, Img3Constants.IMG3_SIGNATURE_LENGTH);
		return Arrays.equals(bytes, Img3Constants.IMG3_SIGNATURE_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		monitor.setMessage("Opening IMG3...");

		this.header = new Img3(provider);

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
			GFileImpl dataFile = GFileImpl.fromPathString(this, root, filename, null, false,
				dataTag.getTotalLength());
			dataFileList.add(dataFile);
		}
	}

	private String getDataTagFilename(DataTag dataTag, int index, boolean isMulti) {
		String filename = dataTag.getMagic();
		return isMulti ? (filename + index) : filename;
	}

	@Override
	public void close() throws IOException {
		super.close();
	}

	@Override
	public InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CryptoException, CancelledException {
		FSRLRoot fsFSRL = getFSRL();
		if (fsFSRL.getNestingDepth() < 3) {
			throw new CryptoException(
				"Unable to decrypt IMG3 data because IMG3 crypto keys are specific to the container it is embedded in and this IMG3 was not in a container");
		}

		List<DataTag> tags = header.getTags(DataTag.class);
		for (int i = 0; i < tags.size(); ++i) {
			DataTag dataTag = tags.get(i);
			String filename = getDataTagFilename(dataTag, i, tags.size() > 1);
			if (file.getName().equals(filename)) {
				FileCacheEntry derivedFile =
					fsService.getDerivedFile(fsFSRL.getContainer(), "decrypted_img3_" + filename,
						(srcFile) -> dataTag.getDecryptedInputStream(fsFSRL.getName(2),
							fsFSRL.getName(1)),
						monitor);

				return new FileInputStream(derivedFile.file);
			}
		}

		throw new IOException("Unable to get DATA for " + file.getPath());
	}

	public Icon getIcon() {
		return null;
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		if (directory == null || directory.equals(root)) {
			if (dataFileList.isEmpty()) {
				if (header != null) {
					List<DataTag> tags = header.getTags(DataTag.class);
					for (int i = 0; i < tags.size(); ++i) {
						DataTag dataTag = tags.get(i);
						String name = dataTag.getMagic();
						if (tags.size() > 1) {
							name = name + i;
						}
						GFileImpl dataFile = GFileImpl.fromFilename(this, root, name, false,
							dataTag.getTotalLength(), null);
						dataFileList.add(dataFile);
					}
				}
			}
			return dataFileList;
		}
		return new ArrayList<>();
	}

	public boolean isDirectory(GFileImpl directory) {
		return directory.equals(root);
	}

	public boolean isFile(GFileImpl file) {
		return !file.equals(root);
	}

}
