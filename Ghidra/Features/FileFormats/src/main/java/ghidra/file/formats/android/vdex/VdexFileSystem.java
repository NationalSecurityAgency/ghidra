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
package ghidra.file.formats.android.vdex;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.file.formats.android.cdex.CDexHeader;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "androidvdex", description = "Android VDEX (for extracting embedded DEX files)", factory = GFileSystemBaseFactory.class)
public class VdexFileSystem extends GFileSystemBase {

	private VdexHeader header;
	private List<GFile> listing = new ArrayList<>();

	public VdexFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		try {
			byte[] magicBytes = provider.readBytes(0, VdexConstants.MAGIC.length());
			return VdexConstants.MAGIC.equals(new String(magicBytes));
		}
		catch (Exception e) {
			// ignore...
		}
		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Parsing VDEX header...");
		BinaryReader reader = new BinaryReader(provider, true /* TODO always LE??? */ );
		try {
			header = VdexFactory.getVdexHeader(reader);
			header.parse(reader, monitor);

			for (int i = 0; i < header.getDexHeaderList().size(); ++i) {
				monitor.checkCanceled();
				DexHeader dexHeader = header.getDexHeaderList().get(i);
				String name =
					((dexHeader instanceof CDexHeader) ? "cdex" + "_" + i : "classes" + i + ".dex");
				GFile file = GFileImpl.fromPathString(this, root, name, null, false,
					Integer.toUnsignedLong(dexHeader.getFileSize()));
				listing.add(file);
			}
		}
		catch (UnsupportedVdexVersionException e) {
			throw new IOException(e);
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		header = null;
		listing.clear();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			return listing;
		}
		return Collections.emptyList();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		int index = listing.indexOf(file);
		if (index < 0) {
			throw new IOException("Unknown file: " + file);
		}
		DexHeader dexHeader = header.getDexHeaderList().get(index);
		long startIndex = header.getDexStartOffset(index);
		return new ByteProviderWrapper(provider, startIndex,
			Integer.toUnsignedLong(dexHeader.getFileSize()), file.getFSRL());
	}

}
