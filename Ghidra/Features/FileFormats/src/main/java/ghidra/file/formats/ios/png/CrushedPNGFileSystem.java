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
package ghidra.file.formats.ios.png;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "crushedpng", description = "Crushed PNG", factory = GFileSystemBaseFactory.class)
public class CrushedPNGFileSystem extends GFileSystemBase {

	private ProcessedPNG png;
	private GFileImpl pngGFile;

	public CrushedPNGFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		super.close();
		pngGFile = null;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		int signatureLength = CrushedPNGConstants.SIGNATURE_BYTES.length;
		byte[] signatureArray = new byte[signatureLength];
		signatureArray = provider.readBytes(0, signatureLength);

		if (Arrays.equals(signatureArray, CrushedPNGConstants.SIGNATURE_BYTES)) {

			//Do a check for the iOS inserted chunk "CgBI" which is inserted
			//before the usual first "IHDR" chunk
			byte[] insertedChunkID = provider.readBytes(signatureArray.length + 4, 4);
			if (Arrays.equals(insertedChunkID, CrushedPNGConstants.INSERTED_IOS_CHUNK)) {
				return true;
			}
			return false;

		}
		return false;

	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, false);

		monitor.setMessage("Opening iOS Crushed PNG...");
		this.png = new ProcessedPNG(reader, monitor);

		String uncrushedPngFilename = getName();

		//Remove the .png extension and then replace with .uncrushed.png extension
		if ("png".equalsIgnoreCase(FilenameUtils.getExtension(uncrushedPngFilename))) {
			uncrushedPngFilename =
				FilenameUtils.removeExtension(uncrushedPngFilename) + ".uncrushed.png";
		}

		pngGFile = GFileImpl.fromFilename(this, root, uncrushedPngFilename, false, 1, null);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) ? Arrays.asList(pngGFile)
				: Collections.emptyList();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		return png.toString();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		CrushedPNGUtil util = new CrushedPNGUtil();
		InputStream is;
		try {
			is = util.getUncrushedPNGBytes(png, monitor);
		}
		catch (Exception e) {

			return null;
		}
		return is;
	}

}
