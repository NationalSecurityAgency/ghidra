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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
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
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		if (file != null) {
			if (file.equals(dexFile)) {
				return new ByteProviderWrapper(provider, odexHeader.getDexOffset(),
					odexHeader.getDexLength(), dexFile.getFSRL());
			}
			if (file.equals(depsFile)) {
				return new ByteProviderWrapper(provider, odexHeader.getDepsOffset(),
					odexHeader.getDepsLength(), depsFile.getFSRL());
			}
			if (file.equals(auxFile)) {
				return new ByteProviderWrapper(provider, odexHeader.getAuxOffset(),
					odexHeader.getAuxLength(), auxFile.getFSRL());
			}
		}
		return null;
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
