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

import org.apache.commons.io.FilenameUtils;

import com.google.common.collect.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.file.formats.ios.dyldcache.DyldCacheExtractor.MappingRange;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystem} implementation for the components of a DYLD Cache
 */
@FileSystemInfo(type = DyldCacheFileSystem.DYLD_CACHE_FSTYPE, description = "iOS DYLD Cache Version 1", factory = GFileSystemBaseFactory.class)
public class DyldCacheFileSystem extends GFileSystemBase {

	public static final String DYLD_CACHE_FSTYPE = "dyldcachev1";

	private SplitDyldCache splitDyldCache;
	private boolean parsedLocalSymbols = false;
	private Map<DyldCacheSlideInfoCommon, List<DyldCacheSlideFixup>> slideFixupMap;
	private Map<GFile, Long> addrMap = new HashMap<>();
	private Map<GFile, Integer> indexMap = new HashMap<>();
	private Map<Long, MappingRange> stubMap = new HashMap<>();
	private Map<Long, MappingRange> dyldDataMap = new HashMap<>();

	/**
	 * Creates a new {@link DyldCacheFileSystem}
	 * 
	 * @param fileSystemName The name of the file system
	 * @param provider The {@link ByteProvider} that contains the file system
	 */
	public DyldCacheFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		slideFixupMap = null;
		parsedLocalSymbols = false;
		addrMap.clear();
		indexMap.clear();
		stubMap.clear();
		dyldDataMap.clear();
		if (splitDyldCache != null) {
			splitDyldCache.close();
			splitDyldCache = null;
		}
		super.close();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws CancelledException, IOException {
		Long addr = addrMap.get(file);
		if (addr == null) {
			return null;
		}
		int index = indexMap.get(file);
		long machHeaderStartIndexInProvider =
			addr - splitDyldCache.getDyldCacheHeader(index).getBaseAddress();

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
			if (stubMap.containsKey(addr)) {
				MappingRange mappingRange = stubMap.get(addr);
				return DyldCacheExtractor.extractMapping(mappingRange, "_STUBS", splitDyldCache,
					index, slideFixupMap, file.getFSRL(), monitor);
			}
			if (dyldDataMap.containsKey(addr)) {
				MappingRange mappingRange = dyldDataMap.get(addr);
				return DyldCacheExtractor.extractMapping(mappingRange, "__DATA", splitDyldCache,
					index, slideFixupMap, file.getFSRL(), monitor);
			}
			return DyldCacheExtractor.extractDylib(machHeaderStartIndexInProvider,
				splitDyldCache, index, slideFixupMap, file.getFSRL(), monitor);
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
		splitDyldCache = new SplitDyldCache(provider, false, new MessageLog(), monitor);
		Map<Integer, List<MappingRange>> dyldDataMappingRanges = new HashMap<>();

		// Find and store all the mappings for the DYLD data subcaches.
		// As we find other components that overlap, these mapping ranges will be reduced so there 
		// is no overlap
		monitor.initialize(splitDyldCache.size(), "Find DYLD data...");
		for (int i = 0; i < splitDyldCache.size(); i++) {
			monitor.increment();
			String name = splitDyldCache.getName(i);
			DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
			List<DyldCacheMappingAndSlideInfo> mappingInfos = header.getCacheMappingAndSlideInfos();
			List<MappingRange> mappingRangeList = new ArrayList<>();
			if (name.endsWith(".dylddata")) {
				dyldDataMappingRanges.put(i, mappingRangeList);
				for (int j = 0; j < mappingInfos.size(); j++) {
					DyldCacheMappingAndSlideInfo mappingInfo = mappingInfos.get(j);
					mappingRangeList.add(new MappingRange(mappingInfo, getRangeSet(mappingInfo)));
				}
			}
		}
		
		// Find DYLIB and STUBS components. Remove DYLIB segment ranges from the DYLD data mappings
		// so we can later add the DYLD data with no overlap.
		// NOTE: The STUBS will never overlap with DYLD data so there is no need to remove STUB
		// segment ranges.
		monitor.initialize(splitDyldCache.size(), "Find DYLD components...");
		for (int i = 0; i < splitDyldCache.size(); i++) {
			monitor.increment();
			String name = splitDyldCache.getName(i);
			DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
			List<DyldCacheMappingAndSlideInfo> mappingInfos = header.getCacheMappingAndSlideInfos();

			// DYLIBs
			List<DyldCacheImage> mappedImages = header.getMappedImages();
			for (DyldCacheImage mappedImage : mappedImages) {
				GFileImpl file =
					GFileImpl.fromPathString(this, root, mappedImage.getPath(), null, false, -1);
				storeFile(file, mappedImage.getAddress(), i);
				reduceOverlappingSegments(i, mappedImage, dyldDataMappingRanges.values());
			}

			// STUBS
			for (DyldCacheMappingAndSlideInfo mappingInfo : mappingInfos) {
				if (mappingInfo.isTextStubs()) {
					GFileImpl file =
						GFileImpl.fromPathString(this, root, getStubPath(name), null, false, -1);
					storeFile(file, mappingInfo.getAddress(), i);
					stubMap.put(mappingInfo.getAddress(),
						new MappingRange(mappingInfo, getRangeSet(mappingInfo)));
					break; // assuming just 1 stub block
				}
			}
		}

		// Add DYLD data components with reduced mapping ranges
		for (Integer i : dyldDataMappingRanges.keySet()) {
			String name = splitDyldCache.getName(i);
			List<MappingRange> mappingRangeList = dyldDataMappingRanges.get(i);
			for (int j = 0; j < mappingRangeList.size(); j++) {
				monitor.checkCancelled();
				MappingRange mappingRange = mappingRangeList.get(j);
				DyldCacheMappingAndSlideInfo mappingInfo = mappingRange.mappingInfo();
				GFileImpl file =
					GFileImpl.fromPathString(this, root, getDyldDataPath(name, j), null, false, -1);
				storeFile(file, mappingInfo.getAddress(), i);
				dyldDataMap.put(mappingInfo.getAddress(), mappingRange);
			}
		}
	}

	/**
	 * Gets the open {@link SplitDyldCache}
	 * 
	 * @return The opened {@link SplitDyldCache}, or null if it has is not open
	 */
	public SplitDyldCache getSplitDyldCache() {
		return splitDyldCache;
	}

	/**
	 * Gets the text stub path for the given DYLD Cache name
	 * 
	 * @param dyldCacheName The name of the DYLD Cache
	 * @return The text stub path for the given DYLD Cache name
	 */
	public static String getStubPath(String dyldCacheName) {
		return "/STUBS/STUBS." + FilenameUtils.getExtension(dyldCacheName);
	}

	/**
	 * Gets the DYLD data path for the given DYLD Cache name
	 * 
	 * @param dyldCacheName The name of the DYLD Cache
	 * @param mappingIndex The mapping index
	 * @return The DYLD data path for the given DYLD Cache name
	 */
	public static String getDyldDataPath(String dyldCacheName, int mappingIndex) {
		return "/DYLD_DATA/DYLD_DATA.%s.%d".formatted(
			FilenameUtils.getExtension(
				dyldCacheName.substring(0, dyldCacheName.length() - ".dylddata".length())),
			mappingIndex);
	}

	/**
	 * "Stores" the given {@link GFile file} and it's parent hierarchy in lookup maps for future
	 * access
	 * 
	 * @param file The {@link GFile file} to store
	 * @param address The address that corresponds to the {@link GFile file}
	 * @param splitDyldCacheIndex The {@link SplitDyldCache} index that corresponds to the given
	 *    {@link GFile file}
	 */
	private void storeFile(GFile file, Long address, Integer splitDyldCacheIndex) {
		if (file == null) {
			return;
		}
		if (file.equals(root)) {
			return;
		}
		if (!addrMap.containsKey(file) || addrMap.get(file) == null) {
			addrMap.put(file, address);
			indexMap.put(file, splitDyldCacheIndex);
		}
		GFile parentFile = file.getParentFile();
		storeFile(parentFile, null, null);
	}

	/**
	 * Gets the default range of the given {@link DyldCacheMappingAndSlideInfo}
	 * 
	 * @param mappingInfo The {@link DyldCacheMappingAndSlideInfo} to the the range of
	 * @return The default range of the given {@link DyldCacheMappingAndSlideInfo}
	 */
	private RangeSet<Long> getRangeSet(DyldCacheMappingAndSlideInfo mappingInfo) {
		RangeSet<Long> rangeSet = TreeRangeSet.create();
		rangeSet.add(Range.openClosed(mappingInfo.getAddress(),
			mappingInfo.getAddress() + mappingInfo.getSize()));
		return rangeSet;
	}

	/**
	 * Reduces the given ranges so they do not overlap with the segments founded in the given image
	 * 
	 * @param splitDyldCacheIndex The {@link SplitDyldCache}
	 * @param mappedImage The {@link DyldCacheImage} that may overlap the given ranges
	 * @param ranges The {@link MappingRange ranges} to reduce
	 * @throws IOException if an exception occurred while parsing the image's Mach-O header
	 */
	private void reduceOverlappingSegments(int splitDyldCacheIndex, DyldCacheImage mappedImage,
			Collection<List<MappingRange>> ranges) throws IOException {
		DyldCacheHeader dyldCacheHeader = splitDyldCache.getDyldCacheHeader(splitDyldCacheIndex);
		ByteProvider p = splitDyldCache.getProvider(splitDyldCacheIndex);
		try {
			MachHeader machoHeader =
				new MachHeader(p, mappedImage.getAddress() - dyldCacheHeader.getBaseAddress());
			for (SegmentCommand segment : machoHeader.parseSegments()) {
				for (List<MappingRange> mappingRanges : ranges) {
					for (MappingRange mappingRange : mappingRanges) {
						Range<Long> range = Range.closedOpen(segment.getVMaddress(),
							segment.getVMaddress() + segment.getVMsize());
						mappingRange.rangeSet().remove(range);
					}
				}
			}
		}
		catch (MachException e) {
			throw new IOException(e);
		}
	}
}
