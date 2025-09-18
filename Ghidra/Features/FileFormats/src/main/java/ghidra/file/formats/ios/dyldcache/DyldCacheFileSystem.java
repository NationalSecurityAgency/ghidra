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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.*;

import com.google.common.collect.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils.DyldCacheImageRecord;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * A {@link GFileSystem} implementation for the components of a DYLD Cache
 */
@FileSystemInfo(
	type = DyldCacheFileSystem.DYLD_CACHE_FSTYPE,
	description = "iOS DYLD Cache Version 1",
	factory = DyldCacheFileSystemFactory.class
)
public class DyldCacheFileSystem extends AbstractFileSystem<DyldCacheEntry> {

	public static final String DYLD_CACHE_FSTYPE = "dyldcachev1";

	private ByteProvider provider;
	private SplitDyldCache splitDyldCache;
	private boolean parsedLocalSymbols = false;
	private Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap;
	private RangeMap<Long, DyldCacheEntry> rangeMap = TreeRangeMap.create();

	/**
	 * Creates a new {@link DyldCacheFileSystem}
	 * 
	 * @param fsFSRL {@link FSRLRoot} of this file system
	 * @param provider The {@link ByteProvider} that contains the file system
	 */
	public DyldCacheFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		super(fsFSRL, FileSystemService.getInstance());
		this.provider = provider;
	}

	/**
	 * Mounts this file system
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException If there was an issue mounting the file system
	 * @throws MachException if there was an error parsing a DYLIB header
	 * @throws CancelledException If the user cancelled the operation
	 */
	public void mount(TaskMonitor monitor) throws IOException, MachException, CancelledException {
		splitDyldCache = new SplitDyldCache(provider, false, new MessageLog(), monitor);
		RangeSet<Long> allDylibRanges = TreeRangeSet.create();

		// Find the DYLIB's and add them as files
		List<DyldCacheImageRecord> imageRecords = splitDyldCache.getImageRecords();
		monitor.initialize(imageRecords.size(), "Find DYLD DYLIBs...");
		for (DyldCacheImageRecord imageRecord : imageRecords) {
			monitor.increment();
			DyldCacheImage image = imageRecord.image();
			MachHeader machHeader = splitDyldCache.getMacho(imageRecord);
			RangeSet<Long> rangeSet = TreeRangeSet.create();
			for (SegmentCommand segment : machHeader.parseSegments()) {
				Range<Long> range = Range.openClosed(segment.getVMaddress(),
					segment.getVMaddress() + segment.getVMsize());
				rangeSet.add(range);
			}
			DyldCacheEntry entry = new DyldCacheEntry(image.getPath(),
				imageRecord.splitCacheIndex(), rangeSet, null, null, -1);
			rangeSet.asRanges().forEach(r -> rangeMap.put(r, entry));
			allDylibRanges.addAll(rangeSet);
			fsIndex.storeFile(image.getPath(), fsIndex.getFileCount(), false, -1, entry);
		}

		// Find and store all the mappings for all of the subcaches. We need to remove the DYLIB's
		// that we just found so we don't account for any bytes more than once.  This will result
		// in the mappings being broken up into a lot of small chunks, each being its own file.
		monitor.initialize(splitDyldCache.size(), "Find DYLD mapping ranges...");
		for (int i = 0; i < splitDyldCache.size(); i++) {
			monitor.increment();
			DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
			String name = splitDyldCache.getName(i);
			List<DyldCacheMappingInfo> mappingInfos = header.getMappingInfos();
			List<DyldCacheMappingAndSlideInfo> mappingAndSlideInfos =
				header.getCacheMappingAndSlideInfos();
			for (int j = 0; j < mappingInfos.size(); j++) {
				DyldCacheMappingInfo mappingInfo = mappingInfos.get(j);
				DyldCacheMappingAndSlideInfo mappingAndSlideInfo =
					!mappingAndSlideInfos.isEmpty() ? mappingAndSlideInfos.get(j) : null;
				Range<Long> mappingRange = Range.openClosed(mappingInfo.getAddress(),
					mappingInfo.getAddress() + mappingInfo.getSize());
				RangeSet<Long> reducedRangeSet = TreeRangeSet.create();
				reducedRangeSet.add(mappingRange);
				reducedRangeSet.removeAll(allDylibRanges);
				for (Range<Long> range : reducedRangeSet.asRanges()) {
					String path =
						getComponentPath(name, mappingInfo, mappingAndSlideInfo, j, range);
					DyldCacheEntry entry = new DyldCacheEntry(path, i,
						TreeRangeSet.create(CollectionUtils.asIterable(range)), mappingInfo,
						mappingAndSlideInfo, j);
					rangeMap.put(range, entry);
					fsIndex.storeFile(path, fsIndex.getFileCount(), false, -1, entry);
				}
			}
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws CancelledException, IOException {
		DyldCacheEntry entry = fsIndex.getMetadata(file);
		if (entry == null) {
			return null;
		}

		if (slideFixupMap == null) {
			slideFixupMap = DyldCacheExtractor.getSlideFixups(splitDyldCache, monitor);
		}

		if (!parsedLocalSymbols) {
			for (int i = 0; i < splitDyldCache.size(); i++) {
				splitDyldCache.getDyldCacheHeader(i)
						.parseLocalSymbolsInfo(true, new MessageLog(), monitor);
			}
			parsedLocalSymbols = true;
		}

		try {
			if (entry.mappingInfo() != null) {
				return DyldCacheExtractor.extractMapping(entry,
					getComponentName(entry.mappingAndSlideInfo()), splitDyldCache, slideFixupMap,
					file.getFSRL(), monitor);
			}
			return DyldCacheExtractor.extractDylib(entry, splitDyldCache, slideFixupMap,
				file.getFSRL(), monitor);
		}
		catch (MachException e) {
			throw new IOException("Invalid Mach-O header detected at: " + entry);
		}
	}

	/**
	 * Attempts to find the given address in the DYLD Cache
	 * 
	 * @param addr The address to find
	 * @return The path of the file within the {@link DyldCacheFileSystem} that contains the given
	 *   address, or null if the address was not found
	 * @throws IOException if an IO-related error occurred
	 */
	public String findAddress(long addr) throws IOException {
		DyldCacheEntry entry = rangeMap.get(addr);
		return entry != null ? entry.path() : null;
	}

	/**
	 * Gets a {@link List} of {@link GFile files} that have the given mapping flags
	 * 
	 * @param flags The desired flags
	 * @return A {@link List} of {@link GFile files} that have the given mapping flags
	 */
	public List<GFile> getFiles(long flags) {
		List<GFile> files = new ArrayList<>();
		for (DyldCacheEntry entry : rangeMap.asMapOfRanges().values()) {
			DyldCacheMappingAndSlideInfo mappingAndSlideInfo = entry.mappingAndSlideInfo();
			if (mappingAndSlideInfo != null && (flags & mappingAndSlideInfo.getFlags()) != 0) {
				Optional.ofNullable(lookup(entry.path())).ifPresent(files::add);
			}
		}
		return files;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		DyldCacheEntry entry = fsIndex.getMetadata(file);
		if (entry != null) {
			result.add(NAME_ATTR, entry.path());
			result.add(PATH_ATTR, entry.path());
			result.add("Cache Index", entry.splitCacheIndex());
			result.add("Address Range", entry.rangeSet().toString()); // TODO: display as hex
		}
		return result;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();

		if (splitDyldCache != null) {
			splitDyldCache.close();
			splitDyldCache = null;
		}
		if (provider != null) {
			provider.close();
			provider = null;
		}

		slideFixupMap = null;
		parsedLocalSymbols = false;
		rangeMap.clear();
	}

	private String getComponentName(DyldCacheMappingAndSlideInfo mappingAndSlideInfo) {
		String name = "DYLD";
		if (mappingAndSlideInfo == null) {
			return name;
		}
		if (mappingAndSlideInfo.isDirtyData()) {
			name = "DATA_DIRTY";
		}
		else if (mappingAndSlideInfo.isConstData()) {
			name = mappingAndSlideInfo.isAuthData() ? "AUTH_CONST" : "DATA_CONST";
		}
		else if (mappingAndSlideInfo.isTextStubs()) {
			name = "TEXT_STUBS";
		}
		else if (mappingAndSlideInfo.isConfigData()) {
			name = "DATA_CONFIG";
		}
		else if (mappingAndSlideInfo.isAuthData()) {
			name = "AUTH";
		}
		else if (mappingAndSlideInfo.isReadOnlyData()) {
			name = "DATA_RO";
		}
		else if (mappingAndSlideInfo.isConstTproData()) {
			name = "DATA_CONST_TPRO";
		}
		return name;
	}

	/**
	 * Gets the DYLD component path of the given DYLD component
	 * 
	 * @param dyldCacheName The name of the DYLD Cache
	 * @param mappingInfo the mapping info
	 * @param mappingAndSlideInfo the mapping and slide info (could be null)
	 * @param mappingIndex The mapping index
	 * @return The DYLD component path of the given DYLD component
	 */
	private String getComponentPath(String dyldCacheName, DyldCacheMappingInfo mappingInfo,
			DyldCacheMappingAndSlideInfo mappingAndSlideInfo, int mappingIndex, Range<Long> range) {
		return "/DYLD/%s/%s.%d.0x%x-0x%x".formatted(dyldCacheName,
			getComponentName(mappingAndSlideInfo), mappingIndex, range.lowerEndpoint(),
			range.upperEndpoint());
	}
}
