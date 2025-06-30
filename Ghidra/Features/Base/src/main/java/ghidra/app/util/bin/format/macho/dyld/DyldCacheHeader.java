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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_header structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
public class DyldCacheHeader implements StructConverter {

	private byte[] magic;
	private int mappingOffset;
	private int mappingCount;
	private int imagesOffsetOld;
	private int imagesCountOld;
	private long dyldBaseAddress;
	private long codeSignatureOffset;
	private long codeSignatureSize;
	private long slideInfoOffset;
	private long slideInfoSize;
	private long localSymbolsOffset;
	private long localSymbolsSize;
	private byte[] uuid;
	private long cacheType;
	private int branchPoolsOffset;
	private int branchPoolsCount;
	private long accelerateInfoAddr_dyldInCacheMH;
	private long accelerateInfoSize_dyldInCacheEntry;
	private long imagesTextOffset;
	private long imagesTextCount;
	private long patchInfoAddr;
	private long patchInfoSize;
	private long otherImageGroupAddrUnused;
	private long otherImageGroupSizeUnused;
	private long progClosuresAddr;
	private long progClosuresSize;
	private long progClosuresTrieAddr;
	private long progClosuresTrieSize;
	private int platform;
	private int dyldInfo;
	private int formatVersion;
	private boolean dylibsExpectedOnDisk;
	private boolean simulator;
	private boolean locallyBuiltCache;
	private boolean builtFromChainedFixups;
	private long sharedRegionStart;
	private long sharedRegionSize;
	private long maxSlide;
	private long dylibsImageArrayAddr;
	private long dylibsImageArraySize;
	private long dylibsTrieAddr;
	private long dylibsTrieSize;
	private long otherImageArrayAddr;
	private long otherImageArraySize;
	private long otherTrieAddr;
	private long otherTrieSize;
	private int mappingWithSlideOffset;
	private int mappingWithSlideCount;
	private long dylibsPBLStateArrayAddrUnused;
	private long dylibsPBLSetAddr;
	private long programsPBLSetPoolAddr;
	private long programsPBLSetPoolSize;
	private long programTrieAddr;
	private int programTrieSize;
	private int osVersion;
	private int altPlatform;
	private int altOsVersion;
	private long swiftOptsOffset;
	private long swiftOptsSize;
	private int subCacheArrayOffset;
	private Integer subCacheArrayCount;
	private byte[] symbolFileUUID;
	private long rosettaReadOnlyAddr;
	private long rosettaReadOnlySize;
	private long rosettaReadWriteAddr;
	private long rosettaReadWriteSize;
	private int imagesOffset;
	private int imagesCount;
	private Integer cacheSubType;
	private long objcOptsOffset;
	private long objcOptsSize;
	private long cacheAtlasOffset;
	private long cacheAtlasSize;
	private long dynamicDataOffset;
	private long dynamicDataMaxSize;
	private int tproMappingsOffset;
	private int tproMappingsCount;
	private long functionVariantInfoAddr;
	private long functionVariantInfoSize;
	private long prewarmingDataOffset;
	private long prewarmingDataSize;

	private int headerSize;
	private BinaryReader reader;
	private long baseAddress;
	private List<DyldCacheMappingInfo> mappingInfoList;
	private List<DyldCacheImageInfo> imageInfoList;
	private List<DyldCacheSlideInfoCommon> slideInfoList;
	private DyldCacheLocalSymbolsInfo localSymbolsInfo;
	private List<Long> branchPoolList;
	private DyldCacheAccelerateInfo accelerateInfo;
	private List<DyldCacheImageTextInfo> imageTextInfoList;
	private List<DyldSubcacheEntry> subcacheEntryList;
	private DyldArchitecture architecture;
	private List<DyldCacheMappingAndSlideInfo> cacheMappingAndSlideInfoList;
	private MemoryBlock fileBlock;

	@SuppressWarnings("unused")
	private int padding;

	/**
	 * Create a new {@link DyldCacheHeader}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD cache header
	 * @throws IOException if there was an IO-related problem creating the DYLD cache header
	 */
	public DyldCacheHeader(BinaryReader reader) throws IOException {
		this.reader = reader;
		long startIndex = reader.getPointerIndex();

		magic = reader.readNextByteArray(16);
		mappingOffset = reader.readNextInt();
		mappingCount = reader.readNextInt();
		imagesOffsetOld = reader.readNextInt();
		imagesCountOld = reader.readNextInt();
		dyldBaseAddress = reader.readNextLong();
		if (reader.getPointerIndex() < mappingOffset) {
			codeSignatureOffset = reader.readNextLong();
			codeSignatureSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			slideInfoOffset = reader.readNextLong();
			slideInfoSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			localSymbolsOffset = reader.readNextLong();
			localSymbolsSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			uuid = reader.readNextByteArray(16);
		}
		if (reader.getPointerIndex() < mappingOffset) {
			cacheType = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			branchPoolsOffset = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			branchPoolsCount = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			accelerateInfoAddr_dyldInCacheMH = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			accelerateInfoSize_dyldInCacheEntry = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			imagesTextOffset = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			imagesTextCount = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			patchInfoAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			patchInfoSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageGroupAddrUnused = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageGroupSizeUnused = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresTrieAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresTrieSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			platform = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dyldInfo = reader.readNextInt();
			formatVersion = dyldInfo & 0xff;
			dylibsExpectedOnDisk = (dyldInfo >>> 8 & 1) == 1;
			simulator = (dyldInfo >>> 9 & 1) == 1;
			locallyBuiltCache = (dyldInfo >> 10 & 1) == 1;
			builtFromChainedFixups = (dyldInfo >> 11 & 1) == 1;
			padding = (dyldInfo >> 12) & 0xfffff;
		}
		if (reader.getPointerIndex() < mappingOffset) {
			sharedRegionStart = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			sharedRegionSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			maxSlide = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsImageArrayAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsImageArraySize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsTrieAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsTrieSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageArrayAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageArraySize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherTrieAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherTrieSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			mappingWithSlideOffset = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			mappingWithSlideCount = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsPBLStateArrayAddrUnused = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsPBLSetAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			programsPBLSetPoolAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			programsPBLSetPoolSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			programTrieAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			programTrieSize = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			osVersion = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			altPlatform = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			altOsVersion = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			swiftOptsOffset = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			swiftOptsSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			subCacheArrayOffset = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			subCacheArrayCount = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			symbolFileUUID = null;
			byte[] temp = reader.readNextByteArray(16);
			for (int i = 0; i < temp.length; i++) {
				if (temp[i] != 0) {
					symbolFileUUID = temp;
					break;
				}
			}
		}
		if (reader.getPointerIndex() < mappingOffset) {
			rosettaReadOnlyAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			rosettaReadOnlySize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			rosettaReadWriteAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			rosettaReadWriteSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			imagesOffset = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			imagesCount = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			cacheSubType = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			padding = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			objcOptsOffset = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			objcOptsSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			cacheAtlasOffset = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			cacheAtlasSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dynamicDataOffset = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dynamicDataMaxSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			tproMappingsOffset = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			tproMappingsCount = reader.readNextInt();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			functionVariantInfoAddr = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			functionVariantInfoSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			prewarmingDataOffset = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			prewarmingDataSize = reader.readNextLong();
		}

		headerSize = (int) (reader.getPointerIndex() - startIndex);

		baseAddress = reader.readLong(mappingOffset);
		architecture = DyldArchitecture.getArchitecture(new String(magic).trim());

		mappingInfoList = new ArrayList<>(mappingCount);
		cacheMappingAndSlideInfoList = new ArrayList<>(mappingWithSlideCount);
		slideInfoList = new ArrayList<>();
		imageInfoList = new ArrayList<>(imagesCountOld);
		branchPoolList = new ArrayList<>(branchPoolsCount);
		imageTextInfoList = new ArrayList<>();
		subcacheEntryList = new ArrayList<>();
	}

	/**
	 * Parses the structures referenced by this {@link DyldCacheHeader} from a file.
	 * 
	 * @param parseLocalSymbols True if local symbols should be parsed; otherwise, false
	 * @param log The log
	 * @param monitor A cancellable task monitor
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void parseFromFile(boolean parseLocalSymbols, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		parseMappingInfo(log, monitor);
		parseImageInfo(log, monitor);
		parseLocalSymbolsInfo(parseLocalSymbols, log, monitor);
		parseBranchPools(log, monitor);
		parseImageTextInfo(log, monitor);
		parseSubcaches(log, monitor);
		parseCacheMappingSlideInfo(log, monitor);
		parseSlideInfos(log, monitor);
	}

	private void parseSlideInfos(MessageLog log, TaskMonitor monitor) {
		if (!hasSlideInfo()) {
			return;
		}
		if (slideInfoOffset != 0 &&
			mappingInfoList.size() > DyldCacheSlideInfoCommon.DATA_PAGE_MAP_ENTRY) {
			DyldCacheMappingInfo mappingInfo =
				mappingInfoList.get(DyldCacheSlideInfoCommon.DATA_PAGE_MAP_ENTRY);
			DyldCacheSlideInfoCommon info = DyldCacheSlideInfoCommon.parseSlideInfo(reader,
				slideInfoOffset, mappingInfo, log, monitor);
			if (info != null) {
				slideInfoList.add(info);
			}
		}
		else if (cacheMappingAndSlideInfoList.size() > 0) {
			for (int i = 0; i < cacheMappingAndSlideInfoList.size(); i++) {
				DyldCacheMappingAndSlideInfo info = cacheMappingAndSlideInfoList.get(i);
				if (info.getSlideInfoFileOffset() == 0) {
					continue;
				}
				DyldCacheSlideInfoCommon slideInfo = DyldCacheSlideInfoCommon.parseSlideInfo(reader,
					info.getSlideInfoFileOffset(), mappingInfoList.get(i), log, monitor);
				if (slideInfo != null) {
					slideInfoList.add(slideInfo);
				}
			}
		}
	}

	private void parseCacheMappingSlideInfo(MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Parsing DYLD cache mapping and slide info...");
		monitor.initialize(mappingWithSlideCount);
		try {
			if (mappingWithSlideCount <= 0) {
				return;
			}
			reader.setPointerIndex(mappingWithSlideOffset);
			for (int i = 0; i < mappingWithSlideCount; ++i) {
				cacheMappingAndSlideInfoList.add(new DyldCacheMappingAndSlideInfo(reader));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_mapping_info.");
		}
	}

	/**
	 * Parses the structures referenced by this {@link DyldCacheHeader} from memory.
	 * 
	 * @param program The {@link Program} whose memory to parse
	 * @param space The {@link Program}'s {@link AddressSpace}
	 * @param log The log
	 * @param monitor A cancellable task monitor
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void parseFromMemory(Program program, AddressSpace space, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		parseAcceleratorInfo(program, space, log, monitor);
	}

	/**
	 * Marks up this {@link DyldCacheHeader} with data structures and comments.
	 * 
	 * @param program The {@link Program} to mark up
	 * @param markupLocalSymbols True if the local symbols should be marked up; otherwise, false
	 * @param space The {@link Program}'s {@link AddressSpace}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, boolean markupLocalSymbols, AddressSpace space,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		markupHeader(program, space, monitor, log);
		markupMappingInfo(program, space, monitor, log);
		markupImageInfo(program, space, monitor, log);
		markupLocalSymbolsInfo(markupLocalSymbols, program, space, monitor, log);
		markupCodeSignature(program, space, monitor, log);
		markupSlideInfo(program, space, monitor, log);
		markupBranchPools(program, space, monitor, log);
		markupAcceleratorInfo(program, space, monitor, log);
		markupImageTextInfo(program, space, monitor, log);
		markupSubcacheEntries(program, space, monitor, log);
		markupCacheMappingSlideInfo(program, space, log, monitor);
	}

	/**
	 * {@return the magic bytes, which contain version information}
	 */
	public byte[] getMagic() {
		return magic;
	}

	/**
	 * {@return the mapping offset}
	 */
	public int getMappingOffset() {
		return mappingOffset;
	}

	/**
	 * {@return the mapping count}
	 */
	public int getMappingCount() {
		return mappingCount;
	}

	/**
	 * {@return the old images offset}
	 */
	public int getImagesOffsetOld() {
		return imagesOffsetOld;
	}

	/**
	 * {@return the old images count}
	 */
	public int getImagesCountOld() {
		return imagesCountOld;
	}

	/**
	 * {@return the dyld base address}
	 */
	public long getDyldBaseAddress() {
		return dyldBaseAddress;
	}

	/**
	 * {@return the code signature offset}
	 */
	public long getCodeSignatureOffset() {
		return codeSignatureOffset;
	}

	/**
	 * {@return the code signature size}
	 */
	public long getCodeSignatureSize() {
		return codeSignatureSize;
	}

	/**
	 * {@return the slide info offset}
	 */
	public long getSlideInfoOffset() {
		return slideInfoOffset;
	}

	/**
	 * {@return the slide info size}
	 */
	public long getSlideInfoSize() {
		return slideInfoSize;
	}

	/**
	 * {@return the local symbols offset}
	 */
	public long getLocalSymbolsOffset() {
		return localSymbolsOffset;
	}

	/**
	 * {@return the local symbols size}
	 */
	public long getLocalSymbolsSize() {
		return localSymbolsSize;
	}

	/**
	 * {@return the UUID, or {@code null} if it is not defined}
	 */
	public byte[] getUUID() {
		return uuid;
	}

	/**
	 * {@return the cache type}
	 */
	public long getCacheType() {
		return cacheType;
	}

	/**
	 * {@return the branch pools offset}
	 */
	public int getBranchPoolsOffset() {
		return branchPoolsOffset;
	}

	/**
	 * {@return the branch pools count}
	 */
	public int getBranchPoolsCount() {
		return branchPoolsCount;
	}

	/**
	 * {@return the old accelerate info address or new address of mach header in dyld cache, or 
	 * {@code null} if it is not defined}
	 */
	public long getAccelerateInfoAddrOrDyldInCacheMH() {
		return accelerateInfoAddr_dyldInCacheMH;
	}

	/**
	 * {@return the old accelerate info size or new address of entry point in dyld cache, or 
	 * {@code null} if it is not defined}
	 */
	public long getAccelerateInfoSizeOrDyldInCacheEntry() {
		return accelerateInfoSize_dyldInCacheEntry;
	}

	/**
	 * {@return the images text offset}
	 */
	public long getImagesTextOffset() {
		return imagesTextOffset;
	}

	/**
	 * {@return the images text count}
	 */
	public long getImagesTextCount() {
		return imagesTextCount;
	}

	/**
	 * {@return the patch info address}
	 */
	public long getPatchInfoAddr() {
		return patchInfoAddr;
	}

	/**
	 * {@return the patch info size}
	 */
	public long getPatchInfoSize() {
		return patchInfoSize;
	}

	/**
	 * {@return the other image group address (unused)}
	 */
	public long getOtherImageGroupAddrUnused() {
		return otherImageGroupAddrUnused;
	}

	/**
	 * {@return the other image group size (unused)}
	 */
	public long getOtherImageGroupSizeUnused() {
		return otherImageGroupSizeUnused;
	}
	
	/**
	 * {@return the program launch closures address}
	 */
	public long getProgClosuresAddr() {
		return progClosuresAddr;
	}

	/**
	 * {@return the program launch closures size}
	 */
	public long getProgClosuresSize() {
		return progClosuresSize;
	}

	/**
	 * {@return the program launch closures trie address}
	 */
	public long getProgClosuresTrieAddr() {
		return progClosuresTrieAddr;
	}

	/**
	 * {@return the program launch closures trie size}
	 */
	public long getProgClosuresTrieSize() {
		return progClosuresTrieSize;
	}

	/**
	 * {@return the platform}
	 */
	public int getPlatform() {
		return platform;
	}

	/**
	 * {@return the dyld info}
	 */
	public int getDyldInfo() {
		return dyldInfo;
	}

	/**
	 * {@return the format version}
	 */
	public int getFormatVersion() {
		return formatVersion;
	}

	/**
	 * {@return the dylibs expected on disk value}
	 */
	public boolean getDylibsExpectedOnDisk() {
		return dylibsExpectedOnDisk;
	}

	/**
	 * {@return the simulator value}
	 */
	public boolean getSimulator() {
		return simulator;
	}

	/**
	 * {@return the locally built cache value}
	 */
	public boolean getLocallyBuildCache() {
		return locallyBuiltCache;
	}

	/**
	 * {@return the built from chained fixups value}
	 */
	public boolean getBuiltFromChainedFixups() {
		return builtFromChainedFixups;
	}

	/**
	 * {@return the shared region start}
	 */
	public long getSharedRegionStart() {
		return sharedRegionStart;
	}

	/**
	 * {@return the shared region size}
	 */
	public long getSharedRegionSize() {
		return sharedRegionSize;
	}

	/**
	 * {@return the max slide}
	 */
	public long getMaxSlide() {
		return maxSlide;
	}

	/**
	 * {@return the dylibs image array address}
	 */
	public long getDylibsImageArrayAddr() {
		return dylibsImageArrayAddr;
	}

	/**
	 * {@return the dylibs image array size}
	 */
	public long getDylibsImageArraySize() {
		return dylibsImageArraySize;
	}

	/**
	 * {@return the dylibs trie address}
	 */
	public long getDylibsTriAddr() {
		return dylibsTrieAddr;
	}

	/**
	 * {@return the dylibs trie size}
	 */
	public long getDylibsTrieSize() {
		return dylibsTrieSize;
	}

	/**
	 * {@return the other image array address}
	 */
	public long getOtherImageArrayAddr() {
		return otherImageArrayAddr;
	}

	/**
	 * {@return the other image array size}
	 */
	public long getOtherImageArraySize() {
		return otherImageArraySize;
	}

	/**
	 * {@return the other trie address}
	 */
	public long getOtherTriAddr() {
		return otherTrieAddr;
	}

	/**
	 * {@return the other trie size}
	 */
	public long getOtherTrieSize() {
		return otherTrieSize;
	}

	/**
	 * {@return the mapping with slide offset}
	 */
	public int getMappingWithSlideOffset() {
		return mappingWithSlideOffset;
	}

	/**
	 * {@return the mapping with slide count}
	 */
	public int getMappingWithSlideCount() {
		return mappingWithSlideCount;
	}

	/**
	 * {@return the dylibs PrebuildLoaderSet state array address (unused), or {@code null} if it is
	 * not defined}
	 */
	public long getDylibsPBLStateArrayAddrUnused() {
		return dylibsPBLStateArrayAddrUnused;
	}

	/**
	 * {@return the dylibs PrebuildLoaderSet set address}
	 */
	public long getDylibsPBLSetAddr() {
		return dylibsPBLSetAddr;
	}

	/**
	 * {@return the programs PrebuildLoaderSet set pool address, or {@code null} if it is not
	 * defined}
	 */
	public long getProgramsPBLSetPoolAddr() {
		return programsPBLSetPoolAddr;
	}

	/**
	 * {@return the programs PrebuildLoaderSet set pool size}
	 */
	public long getProgramsPBLSetPoolSize() {
		return programsPBLSetPoolSize;
	}

	/**
	 * {@return the program trie address}
	 */
	public long getProgramTrieAddr() {
		return programTrieAddr;
	}

	/**
	 * {@return the program trie size}
	 */
	public int getProgramTrieSize() {
		return programTrieSize;
	}

	/**
	 * {@return the OS version}
	 */
	public int getOsVersion() {
		return osVersion;
	}

	/**
	 * {@return the alt platform}
	 */
	public int getAltPlatform() {
		return altPlatform;
	}

	/**
	 * {@return the alt OS version}
	 */
	public int getAltOsVersion() {
		return altOsVersion;
	}

	/**
	 * {@return the swift opts offset}
	 */
	public long getSwiftOptsOffset() {
		return swiftOptsOffset;
	}

	/**
	 * {@return the swift opts size}
	 */
	public long getSwiftOptsSize() {
		return swiftOptsSize;
	}

	/**
	 * {@return the subcache array offset}
	 */
	public int getSubCacheArrayOffset() {
		return subCacheArrayOffset;
	}

	/**
	 * {@return the subcache array count, or {@code null} if it is not defined}
	 */
	public Integer getSubCacheArrayCount() {
		return subCacheArrayCount;
	}

	/**
	 * {@return the symbol file UUID, or {@code null} if it is not defined}
	 */
	public byte[] getSymbolFileUUID() {
		return symbolFileUUID;
	}

	/**
	 * {@return the rosetta read-only address}
	 */
	public long getRosettaReadOnlyAddr() {
		return rosettaReadOnlyAddr;
	}

	/**
	 * {@return the rosetta read-only size}
	 */
	public long getRosettaReadOnlySize() {
		return rosettaReadOnlySize;
	}

	/**
	 * {@return the rosetta read-write address}
	 */
	public long getRosettaReadWriteAddr() {
		return rosettaReadWriteAddr;
	}

	/**
	 * {@return the rosetta read-write size}
	 */
	public long getRosettaReadWriteSize() {
		return rosettaReadWriteSize;
	}

	/**
	 * {@return the images offset}
	 */
	public int getImagesOffset() {
		return imagesOffset;
	}

	/**
	 * {@return the images count}
	 */
	public int getImagesCount() {
		return imagesCount;
	}

	/**
	 * {@return the cache subtype, or {@code null} if it is not defined}
	 */
	public Integer getCacheSubType() {
		return cacheSubType;
	}

	/**
	 * {@return the ObjC opts offset}
	 */
	public long getObjcOptsOffset() {
		return objcOptsOffset;
	}

	/**
	 * {@return the ObjC opts size}
	 */
	public long getObjcOptsSize() {
		return objcOptsSize;
	}

	/**
	 * {@return the cache atlas offset}
	 */
	public long getCacheAtlasOffset() {
		return cacheAtlasOffset;
	}

	/**
	 * {@return the cache atlas size}
	 */
	public long getCacheAtlasSize() {
		return cacheAtlasSize;
	}

	/**
	 * {@return the dynamic data offset}
	 */
	public long getDynamicDataOffset() {
		return dynamicDataOffset;
	}

	/**
	 * {@return the dynamic data max size}
	 */
	public long getDynamicDataMaxSize() {
		return dynamicDataMaxSize;
	}

	/**
	 * {@return the tpro mappings offset}
	 */
	public int getTproMappingsOffset() {
		return tproMappingsOffset;
	}

	/**
	 * {@return the tpro mappings count}
	 */
	public int getTproMappingsCount() {
		return tproMappingsCount;
	}

	/**
	 * {@return the function variant info address}
	 */
	public long getFunctionVariantInfoAddr() {
		return functionVariantInfoAddr;
	}

	/**
	 * {@return the function variant info size}
	 */
	public long getFunctionVariantInfoSize() {
		return functionVariantInfoSize;
	}

	/**
	 * {@return the pre-warming data offset}
	 */
	public long getPreWarmingDataOffset() {
		return prewarmingDataOffset;
	}

	/**
	 * {@return the pre-warming data size}
	 */
	public long getPreWarmingDataSize() {
		return prewarmingDataSize;
	}

	/**
	 * {@return the reader associated with the header}
	 * 
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * {@return the base address of the DYLD cache}
	 * <p>
	 * This is where the cache should be loaded in memory.
	 */
	public long getBaseAddress() {
		return baseAddress;
	}

	/**
	 * Gets the {@link List} of {@link DyldCacheMappingInfo}s.  Requires header to have been parsed.
	 * 
	 * @return The {@link List} of {@link DyldCacheMappingInfo}s
	 */
	public List<DyldCacheMappingInfo> getMappingInfos() {
		return mappingInfoList;
	}

	/**
	 * Gets the {@link List} of {@link DyldCacheImageInfo}s.  Requires header to have been parsed.
	 * 
	 * @return The {@link List} of {@link DyldCacheImageInfo}s
	 */
	public List<DyldCacheImageInfo> getImageInfos() {
		return imageInfoList;
	}

	/**
	 * Gets the {@link List} of {@link DyldSubcacheEntry}s.  Requires header to have been parsed.
	 * 
	 * @return The {@link List} of {@link DyldSubcacheEntry}s
	 */
	public List<DyldSubcacheEntry> getSubcacheEntries() {
		return subcacheEntryList;
	}

	/**
	 * Gets the {@link List} of {@link DyldCacheMappingAndSlideInfo}s.  Requires header to have been parsed.
	 * 
	 * @return The {@link List} of {@link DyldCacheMappingAndSlideInfo}s
	 */
	public List<DyldCacheMappingAndSlideInfo> getCacheMappingAndSlideInfos() {
		return cacheMappingAndSlideInfoList;
	}

	/**
	 * Gets the {@link DyldCacheLocalSymbolsInfo}.
	 * 
	 * @return The {@link DyldCacheLocalSymbolsInfo}.  Could be null if it didn't parse.
	 */
	public DyldCacheLocalSymbolsInfo getLocalSymbolsInfo() {
		return localSymbolsInfo;
	}

	/**
	 * Gets the {@link List} of {@link DyldCacheSlideInfoCommon}s.
	 * 
	 * @return the {@link List} of {@link DyldCacheSlideInfoCommon}s.
	 */
	public List<DyldCacheSlideInfoCommon> getSlideInfos() {
		return slideInfoList;
	}

	/**
	 * Gets the {@link List} of branch pool address.  Requires header to have been parsed.
	 * 
	 * @return The {@link List} of branch pool address
	 */
	public List<Long> getBranchPoolAddresses() {
		return branchPoolList;
	}

	/**
	 * Gets architecture information.
	 * 
	 * @return architecture information
	 */
	public DyldArchitecture getArchitecture() {
		return architecture;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_header", 0);

		// @formatter:off
		addHeaderField(struct, new ArrayDataType(ASCII, 16, 1), "magic","e.g. \"dyld_v0    i386\"");
		addHeaderField(struct, DWORD, "mappingOffset","file offset to first dyld_cache_mapping_info");
		addHeaderField(struct, DWORD, "mappingCount", "number of dyld_cache_mapping_info entries");
		addHeaderField(struct, DWORD, "imagesOffsetOld", "UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing");
		addHeaderField(struct, DWORD, "imagesCountOld", "UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing");
		addHeaderField(struct, QWORD, "dyldBaseAddress","base address of dyld when cache was built");
		addHeaderField(struct, QWORD, "codeSignatureOffset", "file offset of code signature blob");
		addHeaderField(struct, QWORD, "codeSignatureSize","size of code signature blob (zero means to end of file)");
		addHeaderField(struct, QWORD, "slideInfoOffset", "file offset of kernel slid info");
		addHeaderField(struct, QWORD, "slideInfoSize", "size of kernel slid info");
		addHeaderField(struct, QWORD, "localSymbolsOffset","file offset of where local symbols are stored");
		addHeaderField(struct, QWORD, "localSymbolsSize", "size of local symbols information");
		addHeaderField(struct, new ArrayDataType(BYTE, 16, 1), "uuid","unique value for each shared cache file");
		addHeaderField(struct, QWORD, "cacheType", "0 for development, 1 for production, 2 for multi-cache");
		addHeaderField(struct, DWORD, "branchPoolsOffset","file offset to table of uint64_t pool addresses");
		addHeaderField(struct, DWORD, "branchPoolsCount", "number of uint64_t entries");
		if (hasAccelerateInfo()) {
			addHeaderField(struct, QWORD, "accelerateInfoAddr","(unslid) address of optimization info");
			addHeaderField(struct, QWORD, "accelerateInfoSize", "size of optimization info");
		}
		else {
			addHeaderField(struct, QWORD, "dyldInCacheMH","(unslid) address of mach_header of dyld in cache");
			addHeaderField(struct, QWORD, "dyldInCacheEntry", "(unslid) address of entry point (_dyld_start) of dyld in cache");
		}
		addHeaderField(struct, QWORD, "imagesTextOffset","file offset to first dyld_cache_image_text_info");
		addHeaderField(struct, QWORD, "imagesTextCount","number of dyld_cache_image_text_info entries");
		addHeaderField(struct, QWORD, "patchInfoAddr", "(unslid) address of dyld_cache_patch_info");
		addHeaderField(struct, QWORD, "patchInfoSize", "Size of all of the patch information pointed to via the dyld_cache_patch_info");
		addHeaderField(struct, QWORD, "otherImageGroupAddrUnused", "unused");
		addHeaderField(struct, QWORD, "otherImageGroupSizeUnused", "unused");
		addHeaderField(struct, QWORD, "progClosuresAddr", "(unslid) address of list of program launch closures");
		addHeaderField(struct, QWORD, "progClosuresSize", "size of list of program launch closures");
		addHeaderField(struct, QWORD, "progClosuresTrieAddr", "(unslid) address of trie of indexes into program launch closures");
		addHeaderField(struct, QWORD, "progClosuresTrieSize", "size of trie of indexes into program launch closures");
		addHeaderField(struct, DWORD, "platform", "platform number (macOS=1, etc)");
		addHeaderField(struct, DWORD, "dyld_info", "");
		addHeaderField(struct, QWORD, "sharedRegionStart", "base load address of cache if not slid");
		addHeaderField(struct, QWORD, "sharedRegionSize", "overall size of region cache can be mapped into");
		addHeaderField(struct, QWORD, "maxSlide","runtime slide of cache can be between zero and this value");
		addHeaderField(struct, QWORD, "dylibsImageArrayAddr","(unslid) address of ImageArray for dylibs in this cache");
		addHeaderField(struct, QWORD, "dylibsImageArraySize","size of ImageArray for dylibs in this cache");
		addHeaderField(struct, QWORD, "dylibsTrieAddr","(unslid) address of trie of indexes of all cached dylibs");
		addHeaderField(struct, QWORD, "dylibsTrieSize", "size of trie of cached dylib paths");
		addHeaderField(struct, QWORD, "otherImageArrayAddr","(unslid) address of ImageArray for dylibs and bundles with dlopen closures");
		addHeaderField(struct, QWORD, "otherImageArraySize","size of ImageArray for dylibs and bundles with dlopen closures");
		addHeaderField(struct, QWORD, "otherTrieAddr","(unslid) address of trie of indexes of all dylibs and bundles with dlopen closures");
		addHeaderField(struct, QWORD, "otherTrieSize","size of trie of dylibs and bundles with dlopen closures");
		addHeaderField(struct, DWORD, "mappingWithSlideOffset","file offset to first dyld_cache_mapping_and_slide_info");
		addHeaderField(struct, DWORD, "mappingWithSlideCount","number of dyld_cache_mapping_and_slide_info entries");
		addHeaderField(struct, QWORD, "dylibsPBLStateArrayAddrUnused", "unused");
		addHeaderField(struct, QWORD, "dylibsPBLSetAddr", "(unslid) address of PrebuiltLoaderSet of all cached dylibs");
		addHeaderField(struct, QWORD, "programsPBLSetPoolAddr", "(unslid) address of pool of PrebuiltLoaderSet for each program ");
		addHeaderField(struct, QWORD, "programsPBLSetPoolSize", "size of pool of PrebuiltLoaderSet for each program");
		addHeaderField(struct, QWORD, "programTrieAddr", "(unslid) address of trie mapping program path to PrebuiltLoaderSet");
		addHeaderField(struct, DWORD, "programTrieSize", "");
		addHeaderField(struct, DWORD, "osVersion", "OS Version of dylibs in this cache for the main platform");
		addHeaderField(struct, DWORD, "altPlatform", "e.g. iOSMac on macOS");
		addHeaderField(struct, DWORD, "altOsVersion", "e.g. 14.0 for iOSMac");
		addHeaderField(struct, QWORD, "swiftOptsOffset", "file offset to Swift optimizations header");
		addHeaderField(struct, QWORD, "swiftOptsOffset", "size of Swift optimizations header");
		addHeaderField(struct, DWORD, "subCacheArrayOffset", "file offset to first dyld_subcache_entry");
		addHeaderField(struct, DWORD, "subCacheArrayCount", "number of subcache entries");
		addHeaderField(struct, new ArrayDataType(BYTE, 16, 1), "symbolFileUUID","unique value for the shared cache file containing unmapped local symbols");
		addHeaderField(struct, QWORD, "rosettaReadOnlyAddr", "(unslid) address of the start of where Rosetta can add read-only/executable data");
		addHeaderField(struct, QWORD, "rosettaReadOnlySize", "maximum size of the Rosetta read-only/executable region");
		addHeaderField(struct, QWORD, "rosettaReadWriteAddr", "(unslid) address of the start of where Rosetta can add read-write data");
		addHeaderField(struct, QWORD, "rosettaReadWriteSize", "maximum size of the Rosetta read-write region");
		addHeaderField(struct, DWORD, "imagesOffset", "file offset to first dyld_cache_image_info");
		addHeaderField(struct, DWORD, "imagesCount", "number of dyld_cache_image_info entries");
		addHeaderField(struct, DWORD, "cacheSubType", "0 for development, 1 for production, when cacheType is multi-cache(2)");
		addHeaderField(struct, DWORD, "padding", "");
		addHeaderField(struct, QWORD, "objcOptsOffset", "VM offset from cache_header* to ObjC optimizations header");
		addHeaderField(struct, QWORD, "objcOptsSize", "size of ObjC optimizations header");
		addHeaderField(struct, QWORD, "cacheAtlasOffset", "VM offset from cache_header* to embedded cache atlas for process introspection");
		addHeaderField(struct, QWORD, "cacheAtlasSize", "size of embedded cache atlas");
		addHeaderField(struct, QWORD, "dynamicDataOffset", "VM offset from cache_header* to the location of dyld_cache_dynamic_data_header");
		addHeaderField(struct, QWORD, "dynamicDataMaxSize", "maximum size of space reserved from dynamic data");
		addHeaderField(struct, DWORD, "tproMappingsOffset", "file offset to first dyld_cache_tpro_mapping_info");
		addHeaderField(struct, DWORD, "tproMappingsCount", "number of dyld_cache_tpro_mapping_info entries");
		addHeaderField(struct, QWORD, "functionVariantInfoAddr", "(unslid) address of dyld_cache_function_variant_info");
		addHeaderField(struct, QWORD, "functionVariantInfoSize", "Size of all of the variant information pointed to via the dyld_cache_function_variant_info");
		addHeaderField(struct, QWORD, "prewarmingDataOffset", "file offset to dyld_prewarming_header");
		addHeaderField(struct, QWORD, "prewarmingDataSize", "byte size of prewarming data");
		// @formatter:on

		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	private void addHeaderField(StructureDataType struct, DataType dt, String fieldname,
			String comment) {
		if (headerSize > struct.getLength()) {
			struct.add(dt, fieldname, comment);
		}
	}

	private void parseMappingInfo(MessageLog log, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Parsing DYLD mapping info...");
		monitor.initialize(mappingCount);
		try {
			reader.setPointerIndex(mappingOffset);
			for (int i = 0; i < mappingCount; ++i) {
				mappingInfoList.add(new DyldCacheMappingInfo(reader));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_mapping_info.");
		}
	}

	private void parseImageInfo(MessageLog log, TaskMonitor monitor) throws CancelledException {
		int offset = imagesOffset != 0 ? imagesOffset : imagesOffsetOld;
		int count = imagesOffset != 0 ? imagesCount : imagesCountOld;
		if (offset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD image info...");
		monitor.initialize(count);
		try {
			reader.setPointerIndex(offset);
			for (int i = 0; i < count; ++i) {
				imageInfoList.add(new DyldCacheImageInfo(reader));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_image_info.");
		}
	}

	public void parseLocalSymbolsInfo(boolean shouldParse, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (!shouldParse || localSymbolsOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD local symbols info...");
		monitor.initialize(1);
		try {
			reader.setPointerIndex(localSymbolsOffset);
			boolean use64bitOffsets = imagesOffsetOld == 0;
			localSymbolsInfo = new DyldCacheLocalSymbolsInfo(reader, architecture, use64bitOffsets);
			localSymbolsInfo.parse(log, monitor);
			monitor.incrementProgress(1);
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_local_symbols_info.");
		}
	}

	private void parseBranchPools(MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (branchPoolsOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD branch pool addresses...");
		monitor.initialize(branchPoolsCount);
		try {
			reader.setPointerIndex(branchPoolsOffset);
			for (int i = 0; i < branchPoolsCount; ++i) {
				branchPoolList.add(reader.readNextLong());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(), "Failed to parse pool addresses.");
		}
	}

	private void parseImageTextInfo(MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (imagesTextOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD image text info...");
		monitor.initialize(imagesTextCount);
		try {
			reader.setPointerIndex(imagesTextOffset);
			for (int i = 0; i < imagesTextCount; ++i) {
				imageTextInfoList.add(new DyldCacheImageTextInfo(reader));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_image_text_info.");
		}
	}

	private void parseSubcaches(MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (subCacheArrayOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD subcaches...");
		monitor.initialize(subCacheArrayCount);
		try {
			reader.setPointerIndex(subCacheArrayOffset);
			for (int i = 0; i < subCacheArrayCount; ++i) {
				subcacheEntryList.add(new DyldSubcacheEntry(reader));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_subcache_entry.");
		}
	}

	private void parseAcceleratorInfo(Program program, AddressSpace space, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		if (!hasAccelerateInfo() || accelerateInfoAddr_dyldInCacheMH == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD accelerateor info...");
		monitor.initialize(imagesTextCount);
		Address addr = space.getAddress(accelerateInfoAddr_dyldInCacheMH);
		try (ByteProvider bytes = new MemoryByteProvider(program.getMemory(), addr)) {
			BinaryReader memoryReader =
				new BinaryReader(bytes, !program.getLanguage().isBigEndian());
			accelerateInfo = new DyldCacheAccelerateInfo(memoryReader);
			accelerateInfo.parse(program, addr, log, monitor);
			monitor.incrementProgress(1);
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_accelerator_info.");
		}
	}

	private void markupHeader(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) {
		monitor.setMessage("Marking up DYLD header...");
		monitor.initialize(1);
		try {
			DataUtilities.createData(program, space.getAddress(getBaseAddress()), toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			monitor.incrementProgress(1);
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_header.");
		}
	}

	private void markupMappingInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD mapping info...");
		monitor.initialize(mappingInfoList.size());
		try {
			Address addr = fileOffsetToAddr(mappingOffset, program, space);
			for (DyldCacheMappingInfo mappingInfo : mappingInfoList) {
				Data d = DataUtilities.createData(program, addr, mappingInfo.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_mapping_info.");
		}
	}

	private void markupCacheMappingSlideInfo(Program program, AddressSpace space, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Marking up DYLD cache mapping and slide info...");
		monitor.initialize(cacheMappingAndSlideInfoList.size());
		try {
			Address addr = fileOffsetToAddr(mappingWithSlideOffset, program, space);
			for (DyldCacheMappingAndSlideInfo mappingInfo : cacheMappingAndSlideInfoList) {
				Data d = DataUtilities.createData(program, addr, mappingInfo.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_mapping_info.");
		}
	}

	private void markupImageInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD image info...");
		monitor.initialize(imageInfoList.size());
		try {
			Address addr = fileOffsetToAddr(imagesOffset != 0 ? imagesOffset : imagesOffsetOld,
				program, space);
			for (DyldCacheImageInfo imageInfo : imageInfoList) {
				Data d = DataUtilities.createData(program, addr, imageInfo.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing().setComment(addr, CommentType.EOL, imageInfo.getPath());
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_image_info.");
		}
	}

	private void markupCodeSignature(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) {
		monitor.setMessage("Marking up DYLD code signature...");
		monitor.initialize(1);
		try {
			String size = "0x" + Long.toHexString(codeSignatureSize);
			program.getListing()
					.setComment(fileOffsetToAddr(codeSignatureOffset, program, space),
						CommentType.PLATE, "Code Signature (" + size + " bytes)");
			monitor.incrementProgress(1);
		}
		catch (IllegalArgumentException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup code signature.");
		}
	}

	private void markupSlideInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) {
		monitor.setMessage("Marking up DYLD slide info...");
		monitor.initialize(1);
		try {
			if (slideInfoList.size() > 0) {
				for (DyldCacheSlideInfoCommon info : slideInfoList) {
					Address addr = fileOffsetToAddr(info.getSlideInfoOffset(), program, space);
					DataUtilities.createData(program, addr, info.toDataType(), -1,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
			}
			monitor.incrementProgress(1);
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_slide_info.");
		}
	}

	private void markupLocalSymbolsInfo(boolean shouldMarkup, Program program, AddressSpace space,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (!shouldMarkup) {
			return;
		}
		monitor.setMessage("Marking up DYLD local symbols info...");
		monitor.initialize(1);
		try {
			if (localSymbolsInfo != null) {
				Address addr = fileOffsetToAddr(localSymbolsOffset, program, space);
				DataUtilities.createData(program, addr, localSymbolsInfo.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				localSymbolsInfo.markup(program, addr, monitor, log);
			}
			monitor.incrementProgress(1);
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_local_symbols_info.");
		}
	}

	private void markupBranchPools(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD branch pool addresses...");
		monitor.initialize(branchPoolList.size());
		try {
			Address addr = fileOffsetToAddr(branchPoolsOffset, program, space);
			for (int i = 0; i < branchPoolList.size(); i++) {
				Data d = DataUtilities.createData(program, addr, Pointer64DataType.dataType,
					Pointer64DataType.dataType.getLength(),
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup branch pool addresses.");
		}
	}

	private void markupAcceleratorInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD accelerator info...");
		monitor.initialize(1);
		try {
			if (hasAccelerateInfo() && accelerateInfo != null) {
				Address addr = space.getAddress(accelerateInfoAddr_dyldInCacheMH);
				DataUtilities.createData(program, addr, accelerateInfo.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				accelerateInfo.markup(program, addr, monitor, log);
			}
			monitor.incrementProgress(1);
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_accelerator_info.");
		}
	}

	private void markupImageTextInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD image text info...");
		monitor.initialize(imageTextInfoList.size());
		try {
			Address addr = fileOffsetToAddr(imagesTextOffset, program, space);
			for (DyldCacheImageTextInfo imageTextInfo : imageTextInfoList) {
				Data d = DataUtilities.createData(program, addr, imageTextInfo.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing().setComment(addr, CommentType.EOL, imageTextInfo.getPath());
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_image_text_info.");
		}
	}
	
	private void markupSubcacheEntries(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD subcache entries...");
		monitor.initialize(subcacheEntryList.size());
		try {
			Address addr = fileOffsetToAddr(subCacheArrayOffset, program, space);
			for (DyldSubcacheEntry subcacheEntry : subcacheEntryList) {
				Data d = DataUtilities.createData(program, addr, subcacheEntry.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_subcache_entry.");
		}
	}

	/**
	 * Sets the {@link MemoryBlock} associated with this header's FILE block.
	 * 
	 * @param block The {@link MemoryBlock} associated with this header's FILE block
	 */
	public void setFileBlock(MemoryBlock block) {
		fileBlock = block;
	}

	/**
	 * Gets the given file offset's corresponding memory address.
	 *  
	 * @param offset The file offset
	 * @param program The {@link Program}
	 * @param space The {@link AddressSpace}
	 * @return The given file offset's corresponding memory address.  Could be null if it doesn't
	 *   have one.
	 */
	private Address fileOffsetToAddr(long offset, Program program, AddressSpace space) {

		// First check the memory that was supposed to get mapped in
		for (DyldCacheMappingInfo mappingInfo : mappingInfoList) {
			if (offset >= mappingInfo.getFileOffset() &&
				offset < mappingInfo.getFileOffset() + mappingInfo.getSize()) {
				return space.getAddress(
					mappingInfo.getAddress() + (offset - mappingInfo.getFileOffset()));
			}
		}

		// Now check the special FILE memory block that contains bytes that weren't supposed to get
		// mapped in to memory
		if (fileBlock != null) {
			AddressSpace fileSpace = fileBlock.getStart().getAddressSpace();
			try {
				return fileSpace.getAddress(offset);
			}
			catch (AddressOutOfBoundsException e) {
				return null;
			}
		}

		return null;
	}

	/**
	 * Checks to see if any slide info exists
	 * 
	 * @return True if any slide info exists; otherwise, false
	 */
	public boolean hasSlideInfo() {
		if (slideInfoSize != 0) {
			// this is no longer used, but if non-zero, is older format and has slide-info
			return true;
		}
		for (DyldCacheMappingAndSlideInfo info : cacheMappingAndSlideInfoList) {
			if (info.getSlideInfoFileSize() != 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the original unslid load address.  This is found in the first mapping infos.
	 * 
	 * @return the original unslid load address
	 */
	public long unslidLoadAddress() {
		return mappingInfoList.get(0).getAddress();
	}

	/**
	 * Checks to see whether or not this is a subcache
	 * 
	 * @return True if this is a subcache; otherwise, false if it's a base cache
	 */
	public boolean isSubcache() {
		return subCacheArrayCount != null && subCacheArrayCount == 0 && symbolFileUUID == null;
	}

	/**
	 * Checks to see whether or not the old accelerate info fields are being used
	 * 
	 * @return True if the old accelerate info fields are being used; otherwise, false if the new
	 *   dyldInCache fields are being used
	 */
	public boolean hasAccelerateInfo() {
		return cacheSubType == null;
	}
}
