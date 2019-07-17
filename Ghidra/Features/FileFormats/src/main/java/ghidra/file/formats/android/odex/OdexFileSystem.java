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
package ghidra.file.formats.android.odex;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.BoundedInputStream;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "odex", description = "ODEX", factory = GFileSystemBaseFactory.class)
public class OdexFileSystem extends GFileSystemBase {

	private OdexHeader odexHeader;
	private GFileImpl dexFile;
	private GFileImpl depsFile;
	private GFileImpl auxFile;

	public OdexFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		if (file != null) {
			if (file.equals(dexFile)) {
				return new BoundedInputStream(provider.getInputStream(odexHeader.getDexOffset()),
					odexHeader.getDexLength());
			}
			if (file.equals(depsFile)) {
				return new BoundedInputStream(provider.getInputStream(odexHeader.getDepsOffset()),
					odexHeader.getDepsLength());
			}
			if (file.equals(auxFile)) {
				return new BoundedInputStream(provider.getInputStream(odexHeader.getAuxOffset()),
					odexHeader.getAuxLength());
			}
		}
		return null;
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		StringBuilder builder = new StringBuilder();
		builder.append("Magic:       " + odexHeader.getMagic()).append("\n");
		builder.append("Dex Offset:  " + Integer.toHexString(odexHeader.getDexOffset())).append(
			"\n");
		builder.append("Dex Length:  " + Integer.toHexString(odexHeader.getDexLength())).append(
			"\n");
		builder.append("Deps Offset: " + Integer.toHexString(odexHeader.getDepsOffset())).append(
			"\n");
		builder.append("Deps Length: " + Integer.toHexString(odexHeader.getDepsLength())).append(
			"\n");
		builder.append("Aux Offset:  " + Integer.toHexString(odexHeader.getAuxOffset())).append(
			"\n");
		builder.append("Aux Length:  " + Integer.toHexString(odexHeader.getAuxLength())).append(
			"\n");
		builder.append("Flags:       " + Integer.toHexString(odexHeader.getFlags())).append("\n");
		return builder.toString();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		List<GFile> list = new ArrayList<>();
		if (directory == null || directory.equals(root)) {
			list.add(dexFile);
			list.add(depsFile);
			list.add(auxFile);
		}
		return list;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		return OdexConstants.isOdexFile(provider);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {

		BinaryReader reader = new BinaryReader(provider, true);
		odexHeader = new OdexHeader(reader);
		dexFile = GFileImpl.fromFilename(this, root, "dex", false, odexHeader.getDexLength(), null);
		depsFile =
			GFileImpl.fromFilename(this, root, "deps", false, odexHeader.getDepsLength(), null);
		auxFile = GFileImpl.fromFilename(this, root, "aux", false, odexHeader.getAuxLength(), null);
	}

	@Override
	public void close() throws IOException {
		super.close();
		odexHeader = null;
		dexFile = null;
	}

}
