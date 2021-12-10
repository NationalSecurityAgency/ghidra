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
package ghidra.file.formats.yaffs2;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "yaffs2", description = "YAFFS2", factory = GFileSystemBaseFactory.class)
public class YAFFS2FileSystem extends GFileSystemBase {

	private Map<Long, GFileImpl> map = new HashMap<>();
	private Map<GFile, YAFFS2Entry> map2 = new HashMap<>();

	public YAFFS2FileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, YAFFS2Constants.MAGIC_SIZE);
		// check for initial byte equal to 0x03, 'directory'
		// and check that the first byte of the file name is null
		// ... this is the yaffs2 root level dir header
		return ((bytes[0] == 0x03) && (bytes[10] == 0x00));
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CancelledException {
		// TODO: should yaffsInput be closed?
		YAFFS2InputStream yaffs2Input = new YAFFS2InputStream(provider.getInputStream(0));

		// go through the image file, looking at each header entry, ignoring the data, storing the dir tree
		while (!monitor.isCancelled()) {
			YAFFS2Entry headerEntry = yaffs2Input.getNextHeaderEntry();
			if (headerEntry == null) {
				break;
			}
			storeEntry(headerEntry, monitor);
		}
	}

	@Override
	public void close() throws IOException {
		map.clear();
		map2.clear();
		super.close();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			List<GFile> roots = new ArrayList<>();
			for (Long objId : map.keySet()) {
				GFile parentFile = map.get(objId).getParentFile();
				if (parentFile != null) {
					if (parentFile == root || parentFile.equals(root)) {
						GFile file = map.get(objId);
						roots.add(file);
					}
				}
			}
			return roots;
		}
		List<GFile> fileList = new ArrayList<>();
		for (Long objId : map.keySet()) {
			GFile parentFile = map.get(objId).getParentFile();
			if (parentFile == null) {
				continue;
			}
			if (parentFile.equals(directory)) {
				GFile file = map.get(objId);
				fileList.add(file);
			}
		}
		return fileList;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		// get saved entry from selected file
		YAFFS2Entry entry = map2.get(file);

		// exit if selection is a directory
		if (entry.isDirectory()) {
			throw new IOException(file.getName() + " is a directory");
		}

		// recall size of file and offset into the file system image
		long fileOffset = entry.getFileOffset();
		long size = entry.getSize();

		// return bytes for the selected file
		try (YAFFS2InputStream YAFFS2Input = new YAFFS2InputStream(provider.getInputStream(0))) {
			byte[] entryData = YAFFS2Input.getEntryData(fileOffset, size);
			return new ByteArrayProvider(entryData, file.getFSRL());
		}
	}

	private void storeEntry(YAFFS2Entry entry, TaskMonitor monitor) {
		if (entry == null) {
			return;
		}
		monitor.setMessage(entry.getName());

		// search the file listing for the parent object ID (need this since yaffs2 file names are not full paths)
		long parentObjectId = entry.getParentObjectId();
		long objectId = entry.getObjectId();
		GFile parentFile = (parentObjectId == 1) ? root : map.get(parentObjectId);

		// skip the first header (always a meaningless, "root" header)
		if ((objectId == 1) & (parentObjectId == 1)) {
			return;
		}

		// process the other headers
		GFileImpl file = GFileImpl.fromFilename(this, parentFile, entry.getName(),
			entry.isDirectory(), entry.getSize(), null);
		map.put(entry.getObjectId(), file);
		map2.put(file, entry);
	}
}
