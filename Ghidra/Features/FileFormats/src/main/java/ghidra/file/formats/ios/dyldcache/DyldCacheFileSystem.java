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
import ghidra.app.util.bin.format.macho.dyld.DyldCacheImageInfo;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "dyldcachev1", description = "iOS DYLD Cache Version 1", factory = GFileSystemBaseFactory.class)
public class DyldCacheFileSystem extends GFileSystemBase {

	private DyldCacheHeader header;
	private Map<GFile, DyldCacheImageInfo> map = new HashMap<>();

	public DyldCacheFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		map.clear();
		super.close();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		DyldCacheImageInfo data = map.get(file);
		if (data == null) {
			return null;
		}
		long machHeaderStartIndexInProvider = data.getAddress() - header.getBaseAddress();
		try {
			return DyldCacheDylibExtractor.extractDylib(machHeaderStartIndexInProvider, provider,
				file.getFSRL(), monitor);
		}
		catch (MachException e) {
			throw new IOException("Invalid Mach-O header detected at 0x" +
				Long.toHexString(machHeaderStartIndexInProvider));
		}
	}

/*
// TODO: support GFileSystemProgramProvider interface?
// Below is commented out implementation of getProgram(), that was present as a comment
// in the previous code, but formatted here so it can be read.
// This needs to be researched and the junit test needs to adjusted to test this.
	@Override
	public Program getProgram(GFile file, LanguageService languageService, TaskMonitor monitor,
			Object consumer) throws Exception {
		DyldArchitecture architecture = header.getArchitecture();
		LanguageCompilerSpecPair lcs = architecture.getLanguageCompilerSpecPair(languageService);
		DyldCacheData dyldCacheData = map.get(file);
		long machHeaderStartIndexInProvider =
			dyldCacheData.getLibraryOffset() - header.getBaseAddress();
		ByteProvider wrapper =
			new ByteProviderWrapper(provider, machHeaderStartIndexInProvider, file.getLength());
		MachHeader machHeader =
			MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, wrapper);
		Program program =
			new ProgramDB(file.getName(), lcs.getLanguage(), lcs.getCompilerSpec(), consumer);
		int id = program.startTransaction(getName());
		boolean success = false;
		try {
			MachoLoader loader = new MachoLoader();
			loader.load(machHeader, program, new MessageLog(), monitor);
			program.setExecutableFormat(MachoLoader.MACH_O_NAME);
			program.setExecutablePath(file.getAbsolutePath());
			success = true;
		}
		finally {
			program.endTransaction(id, success);
			if (!success) {
				program.release(consumer);
			}
		}
		return program;
	}
*/

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			List<GFile> roots = new ArrayList<>();
			for (GFile file : map.keySet()) {
				if (file.getParentFile() == root || file.getParentFile().equals(root)) {
					roots.add(file);
				}
			}
			return roots;
		}
		List<GFile> tmp = new ArrayList<>();
		for (GFile file : map.keySet()) {
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
		return DyldCacheUtils.isDyldCache(provider);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Opening DYLD cache...");

		BinaryReader reader = new BinaryReader(provider, true);

		header = new DyldCacheHeader(reader);
		header.parseFromFile(false, new MessageLog(), monitor);

		List<DyldCacheImageInfo> dataList = header.getImageInfos();

		monitor.initialize(dataList.size());

		for (DyldCacheImageInfo data : dataList) {

			if (monitor.isCancelled()) {
				break;
			}

			monitor.incrementProgress(1);

			GFileImpl file = GFileImpl.fromPathString(this, root, data.getPath(), null, false, -1);
			storeFile(file, data);
		}
	}

	private void storeFile(GFile file, DyldCacheImageInfo data) {
		if (file == null) {
			return;
		}
		if (file.equals(root)) {
			return;
		}
		if (!map.containsKey(file) || map.get(file) == null) {
			map.put(file, data);
		}
		GFile parentFile = file.getParentFile();
		storeFile(parentFile, null);
	}
}
