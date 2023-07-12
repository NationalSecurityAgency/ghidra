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
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_header structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/cache-builder/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
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
	private int dyld_info;
	private int formatVersion;
	private boolean dylibsExpectedOnDisk;
	private boolean simulator;
	private boolean locallyBuiltCache;
	private boolean builtFromChainedFixups;
	private int padding;
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
			dyld_info = reader.readNextInt();
			formatVersion = dyld_info & 0xff;
			dylibsExpectedOnDisk = (dyld_info >>> 8 & 1) == 1;
			simulator = (dyld_info >>> 9 & 1) == 1;
			locallyBuiltCache = (dyld_info >> 10 & 1) == 1;
			builtFromChainedFixups = (dyld_info >> 11 & 1) == 1;
			padding = (dyld_info >> 12) & 0xfffff;
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

	private void parseSlideInfos(MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (!hasSlideInfo()) {
			return;
		}
		if (slideInfoOffset != 0) {
			DyldCacheSlideInfoCommon slideInfo = parseSlideInfo(slideInfoOffset, log, monitor);
			if (slideInfo != null) {
				slideInfoList.add(slideInfo);
			}
		}
		else if (cacheMappingAndSlideInfoList.size() > 0) {
			// last section contains the real slide infos
			int listLen = cacheMappingAndSlideInfoList.size();
			DyldCacheMappingAndSlideInfo linkEditInfo =
				cacheMappingAndSlideInfoList.get(listLen - 1);
			for (DyldCacheMappingAndSlideInfo info : cacheMappingAndSlideInfoList) {
				if (info.getSlideInfoFileOffset() == 0) {
					continue;
				}
				long offsetInEditRegion =
					info.getSlideInfoFileOffset() - linkEditInfo.getSlideInfoFileOffset();
				DyldCacheSlideInfoCommon slideInfo =
					parseSlideInfo(info.getSlideInfoFileOffset(), log, monitor);
				slideInfoList.add(slideInfo);
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
	 * Gets the base address of the DYLD cache.  This is where the cache should be loaded in
	 * memory.
	 * 
	 * @return The base address of the DYLD cache
	 */
	public long getBaseAddress() {
		return baseAddress;
	}

	/**
	 * Gets the magic bytes, which contain version information.
	 * 
	 * @return The magic bytes
	 */
	public byte[] getMagic() {
		return magic;
	}

	/**
	 * Gets the UUID in {@link String} form
	 * 
	 * @return The UUID in {@link String} form, or null if a UUID is not defined
	 */
	public String getUUID() {
		return NumericUtilities.convertBytesToString(uuid);
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
	 * Gets the file offset to first {@link DyldCacheImageInfo}.
	 * 
	 * @return The file offset to first {@link DyldCacheImageInfo}
	 */
	public int getImagesOffset() {
		if (imagesOffset != 0) {
			return imagesOffset;
		}
		return imagesOffsetOld;
	}

	/**
	 * Gets the number of {@link DyldCacheImageInfo}s.
	 * 
	 * @return The number of {@link DyldCacheImageInfo}s
	 */
	public int getImagesCount() {
		if (imagesOffset != 0) {
			return imagesCount;
		}
		return imagesCountOld;
	}

	/**
	 * Generates a {@link List} of {@link DyldCacheImage}s that are mapped in by this 
	 * {@link DyldCacheHeader}.  Requires header to have been parsed.
	 * <p>
	 * NOTE: A DYLD subcache header may declare an image, but that image may get loaded at an
	 * address defined by the memory map of a different subcache header.  This method will only 
	 * return the images that are mapped by "this" header's memory map.
	 * 
	 * @return A {@link List} of {@link DyldCacheImage}s mapped by this {@link DyldCacheHeader}
	 */
	public List<DyldCacheImage> getMappedImages() {
		// NOTE: A subcache will have an entry for every image, but not every image will be mapped
		List<DyldCacheImage> images = new ArrayList<>();
		for (DyldCacheImage imageInfo : imageInfoList) {
			for (DyldCacheMappingInfo mappingInfo : mappingInfoList) {
				if (mappingInfo.contains(imageInfo.getAddress())) {
					images.add(imageInfo);
					break;
				}
			}
		}
		return images;
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
	 * Gets the symbol file UUID in {@link String} form
	 * 
	 * @return The symbol file UUID in {@link String} form, or null if a symbol file UUID is not 
	 *    defined or is all zeros
	 */
	public String getSymbolFileUUID() {
		return NumericUtilities.convertBytesToString(symbolFileUUID);
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
	 * @return The {@link DyldCacheLocalSymbolsInfo}.  Could be be null if it didn't parse. 
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
		addHeaderField(struct, QWORD, "cacheType", "0 for development, 1 for production");
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

	private DyldCacheSlideInfoCommon parseSlideInfo(long offset, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		DyldCacheSlideInfoCommon slideInfo =
			DyldCacheSlideInfoCommon.parseSlideInfo(reader, offset, log, monitor);
		return slideInfo;
	}

	private void parseLocalSymbolsInfo(boolean shouldParse, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (!shouldParse || localSymbolsOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD local symbols info...");
		monitor.initialize(1);
		try {
			reader.setPointerIndex(localSymbolsOffset);
			localSymbolsInfo = new DyldCacheLocalSymbolsInfo(reader, architecture);
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
			MessageLog log) throws CancelledException {
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
				program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, imageInfo.getPath());
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
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD code signature...");
		monitor.initialize(1);
		try {
			String size = "0x" + Long.toHexString(codeSignatureSize);
			program.getListing()
					.setComment(fileOffsetToAddr(codeSignatureOffset, program, space),
						CodeUnit.PLATE_COMMENT, "Code Signature (" + size + " bytes)");
			monitor.incrementProgress(1);
		}
		catch (IllegalArgumentException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup code signature.");
		}
	}

	private void markupSlideInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
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
			for (Long element : branchPoolList) {
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
				program.getListing()
						.setComment(addr, CodeUnit.EOL_COMMENT, imageTextInfo.getPath());
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
