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
package ghidra.file.formats.ios.dyldcache;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheImage;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "dyldcachev1", description = "iOS DYLD Cache Version 1", factory = GFileSystemBaseFactory.class)
public class DyldCacheFileSystem extends GFileSystemBase {

	private SplitDyldCache splitDyldCache;
	private Map<GFile, Long> addrMap = new HashMap<>();
	private Map<GFile, Integer> indexMap = new HashMap<>();

	public DyldCacheFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		addrMap.clear();
		indexMap.clear();
		splitDyldCache.close();
		super.close();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		Long addr = addrMap.get(file);
		if (addr == null) {
			return null;
		}
		int index = indexMap.get(file);
		long machHeaderStartIndexInProvider =
			addr - splitDyldCache.getDyldCacheHeader(index).getBaseAddress();
		try {
			return DyldCacheDylibExtractor.extractDylib(machHeaderStartIndexInProvider,
				splitDyldCache, index, file.getFSRL(), monitor);
		}
		catch (MachException e) {
			throw new IOException("Invalid Mach-O header detected at 0x" +
				Long.toHexString(machHeaderStartIndexInProvider));
		}
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			List<GFile> roots = new ArrayList<>();
			for (GFile file : addrMap.keySet()) {
				if (file.getParentFile() == root || file.getParentFile().equals(root)) {
					roots.add(file);
				}
			}
			return roots;
		}
		List<GFile> tmp = new ArrayList<>();
		for (GFile file : addrMap.keySet()) {
			if (file.getParentFile() == null) {
				continue;
			}
			if (file.getParentFile().equals(directory)) {
				tmp.add(file);
			}
		}
		return tmp;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		if (!DyldCacheUtils.isDyldCache(provider)) {
			return false;
		}
		try {
			DyldCacheHeader header = new DyldCacheHeader(new BinaryReader(provider, true));
			return !header.isSubcache();
		}
		catch (IOException e) {
			return false;
		}
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		MessageLog log = new MessageLog();
		monitor.setMessage("Opening DYLD cache...");
		
		splitDyldCache = new SplitDyldCache(provider, false, log, monitor);
		for (int i = 0; i < splitDyldCache.size(); i++) {
			DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
			monitor.setMessage("Find files...");
			List<DyldCacheImage> mappedImages = header.getMappedImages();
			monitor.initialize(mappedImages.size());
			for (DyldCacheImage mappedImage : mappedImages) {
				GFileImpl file =
					GFileImpl.fromPathString(this, root, mappedImage.getPath(), null, false, -1);
				storeFile(file, mappedImage.getAddress(), i);
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
	}

	private void storeFile(GFile file, Long addr, Integer index) {
		if (file == null) {
			return;
		}
		if (file.equals(root)) {
			return;
		}
		if (!addrMap.containsKey(file) || addrMap.get(file) == null) {
			addrMap.put(file, addr);
			indexMap.put(file, index);
		}
		GFile parentFile = file.getParentFile();
		storeFile(parentFile, null, null);
	}
}
