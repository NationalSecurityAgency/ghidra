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
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_header structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-852.2/dyld3/shared-cache/dyld_cache_format.h.auto.html">dyld3/shared-cache/dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheHeader implements StructConverter {

	private byte[] magic;
	private int mappingOffset;
	private int mappingCount;
	private int imagesOffset;
	private int imagesCount;
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
	private long accelerateInfoAddr;
	private long accelerateInfoSize;
	private long imagesTextOffset;
	private long imagesTextCount;
	private long patchInfoAddr;
	private long patchInfoSize;
	private long otherImageGroupAddrUnused;    // unused
	private long otherImageGroupSizeUnused;    // unused
	private long progClosuresAddr;
	private long progClosuresSize;
	private long progClosuresTrieAddr;
	private long progClosuresTrieSize;
	private int platform;
	private int dyld_info;
	private int formatVersion;                 // Extracted from dyld_info
	private boolean dylibsExpectedOnDisk;      // Extracted from dyld_info
	private boolean simulator;                 // Extracted from dyld_info
	private boolean locallyBuiltCache;         // Extracted from dyld_info
	private boolean builtFromChainedFixups;    // Extracted from dyld_info
	private int padding;                       // Extracted from dyld_info
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

	private int headerType;
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
	private DyldArchitecture architecture;
	private List<DyldCacheMappingAndSlideInfo> cacheMappingAndSlideInfoList;

	/**
	 * Create a new {@link DyldCacheHeader}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD cache header
	 * @throws IOException if there was an IO-related problem creating the DYLD cache header
	 */
	public DyldCacheHeader(BinaryReader reader) throws IOException {
		this.reader = reader;
		long startIndex = reader.getPointerIndex();

		// HEADER 1: https://opensource.apple.com/source/dyld/dyld-95.3/launch-cache/dyld_cache_format.h.auto.html
		headerType = 1;
		magic = reader.readNextByteArray(16);
		mappingOffset = reader.readNextInt();
		mappingCount = reader.readNextInt();
		imagesOffset = reader.readNextInt();
		imagesCount = reader.readNextInt();
		dyldBaseAddress = reader.readNextLong();

		// HEADER 2: https://opensource.apple.com/source/dyld/dyld-195.5/launch-cache/dyld_cache_format.h.auto.html
		if (reader.getPointerIndex() < mappingOffset) {
			headerType = 2;
			codeSignatureOffset = reader.readNextLong();
			codeSignatureSize = reader.readNextLong();
		}
		if (reader.getPointerIndex() < mappingOffset) {
			slideInfoOffset = reader.readNextLong();
			slideInfoSize = reader.readNextLong();
		}

		// HEADER 3:  No header file for this version (without the following UUID), but there are images of this version
		if (reader.getPointerIndex() < mappingOffset) {
			headerType = 3;
			localSymbolsOffset = reader.readNextLong();
			localSymbolsSize = reader.readNextLong();
		}

		// HEADER 4: https://opensource.apple.com/source/dyld/dyld-239.3/launch-cache/dyld_cache_format.h.auto.html
		if (reader.getPointerIndex() < mappingOffset) {
			headerType = 4;
			uuid = reader.readNextByteArray(16);
		}

		// HEADER 5: https://opensource.apple.com/source/dyld/dyld-360.14/launch-cache/dyld_cache_format.h.auto.html
		if (reader.getPointerIndex() < mappingOffset) {
			headerType = 5;
			cacheType = reader.readNextLong();
		}

		// HEADER 6: https://opensource.apple.com/source/dyld/dyld-421.1/launch-cache/dyld_cache_format.h.auto.html
		if (reader.getPointerIndex() < mappingOffset) {
			headerType = 6;
			branchPoolsOffset = reader.readNextInt();
			branchPoolsCount = reader.readNextInt();
			accelerateInfoAddr = reader.readNextLong();
			accelerateInfoSize = reader.readNextLong();
			imagesTextOffset = reader.readNextLong();
			imagesTextCount = reader.readNextLong();
		}

		// HEADER 7: https://opensource.apple.com/source/dyld/dyld-832.7.1/dyld3/shared-cache/dyld_cache_format.h.auto.html
		if (reader.getPointerIndex() < mappingOffset) {
			headerType = 7;
		}
		if (reader.getPointerIndex() < mappingOffset) {
			patchInfoAddr = reader.readNextLong();          // (unslid) address of dyld_cache_patch_info
		}
		if (reader.getPointerIndex() < mappingOffset) {
			patchInfoSize = reader.readNextLong();          // Size of all of the patch information pointed to via the dyld_cache_patch_info
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageGroupAddrUnused = reader.readNextLong();    // unused
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageGroupSizeUnused = reader.readNextLong();    // unused
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresAddr = reader.readNextLong();       // (unslid) address of list of program launch closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresSize = reader.readNextLong();       // size of list of program launch closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresTrieAddr = reader.readNextLong();   // (unslid) address of trie of indexes into program launch closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			progClosuresTrieSize = reader.readNextLong();   // size of trie of indexes into program launch closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			platform = reader.readNextInt();               // platform number (macOS=1, etc)
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dyld_info = reader.readNextInt();
			formatVersion = dyld_info & 0xff;          // dyld3::closure::kFormatVersion
			dylibsExpectedOnDisk = (dyld_info >>> 8 & 1) == 1;  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
			simulator = (dyld_info >>> 9 & 1) == 1;  // for simulator of specified platform
			locallyBuiltCache = (dyld_info >> 10 & 1) == 1;  // 0 for B&I built cache, 1 for locally built cache
			builtFromChainedFixups = (dyld_info >> 11 & 1) == 1;  // some dylib in cache was built using chained fixups, so patch tables must be used for overrides
			padding = (dyld_info >> 12) & 0xfffff; // TBD
		}
		if (reader.getPointerIndex() < mappingOffset) {
			sharedRegionStart = reader.readNextLong();      // base load address of cache if not slid
		}
		if (reader.getPointerIndex() < mappingOffset) {
			sharedRegionSize = reader.readNextLong();       // overall size of region cache can be mapped into
		}
		if (reader.getPointerIndex() < mappingOffset) {
			maxSlide = reader.readNextLong();               // runtime slide of cache can be between zero and this value
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsImageArrayAddr = reader.readNextLong();   // (unslid) address of ImageArray for dylibs in this cache
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsImageArraySize = reader.readNextLong();   // size of ImageArray for dylibs in this cache
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsTrieAddr = reader.readNextLong();         // (unslid) address of trie of indexes of all cached dylibs
		}
		if (reader.getPointerIndex() < mappingOffset) {
			dylibsTrieSize = reader.readNextLong();         // size of trie of cached dylib paths
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageArrayAddr = reader.readNextLong();    // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherImageArraySize = reader.readNextLong();    // size of ImageArray for dylibs and bundles with dlopen closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherTrieAddr = reader.readNextLong();          // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			otherTrieSize = reader.readNextLong();          // size of trie of dylibs and bundles with dlopen closures
		}
		if (reader.getPointerIndex() < mappingOffset) {
			mappingWithSlideOffset = reader.readNextInt(); // file offset to first dyld_cache_mapping_and_slide_info
		}
		if (reader.getPointerIndex() < mappingOffset) {
			mappingWithSlideCount = reader.readNextInt();  // number of dyld_cache_mapping_and_slide_info entries
		}

		headerSize = (int) (reader.getPointerIndex() - startIndex);

		baseAddress = reader.readLong(mappingOffset);
		architecture = DyldArchitecture.getArchitecture(new String(magic).trim());

		mappingInfoList = new ArrayList<>(mappingCount);
		cacheMappingAndSlideInfoList = new ArrayList<>(mappingWithSlideCount);
		slideInfoList = new ArrayList<>();
		imageInfoList = new ArrayList<>(imagesCount);
		branchPoolList = new ArrayList<>(branchPoolsCount);
		imageTextInfoList = new ArrayList<>();
	}

	/**
	 * Parses the structures referenced by this {@link DyldCacheHeader} from a file.
	 * 
	 * @param parseSymbols True if symbols should be parsed (could be very slow); otherwise, false
	 * @param log The log
	 * @param monitor A cancellable task monitor
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void parseFromFile(boolean parseSymbols, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (headerType >= 1) {
			parseMappingInfo(log, monitor);
			parseImageInfo(log, monitor);
		}
		if (headerType >= 3) {
			if (parseSymbols) {
				parseLocalSymbolsInfo(log, monitor);
			}
		}
		if (headerType >= 6) {
			parseBranchPools(log, monitor);
			parseImageTextInfo(log, monitor);
		}
		parseCacheMappingSlideInfo(log, monitor);
		if (haSlideInfo()) {
			parseSlideInfos(log, monitor);
		}
	}

	private void parseSlideInfos(MessageLog log, TaskMonitor monitor) throws CancelledException {
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
				monitor.checkCanceled();
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
		if (headerType >= 6) {
			parseAcceleratorInfo(program, space, log, monitor);
		}
	}

	/**
	 * Marks up this {@link DyldCacheHeader} with data structures and comments.
	 * 
	 * @param program The {@link Program} to mark up
	 * @param space The {@link Program}'s {@link AddressSpace}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, AddressSpace space, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (headerType >= 1) {
			markupHeader(program, space, monitor, log);
			markupMappingInfo(program, space, monitor, log);
			markupImageInfo(program, space, monitor, log);
		}
		if (headerType >= 2) {
			markupCodeSignature(program, space, monitor, log);
			markupSlideInfo(program, space, monitor, log);
		}
		if (headerType >= 3) {
			markupLocalSymbolsInfo(program, space, monitor, log);
		}
		if (headerType >= 6) {
			markupBranchPools(program, space, monitor, log);
			markupAcceleratorInfo(program, space, monitor, log);
			markupImageTextInfo(program, space, monitor, log);
		}
		if (mappingWithSlideOffset >= 0) {
			markupCacheMappingSlideInfo(program, space, log, monitor);
		}
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
		return imagesOffset;
	}

	/**
	 * Gets the number of {@link DyldCacheImageInfo}s.
	 * 
	 * @return The number of {@link DyldCacheImageInfo}s
	 */
	public int getImagesCount() {
		return imagesCount;
	}

	/**
	 * Generates a {@link List} of {@link DyldCacheImage}s that are mapped in by this 
	 * {@link DyldCacheHeader}.  Requires header to have been parsed.
	 * <p>
	 * NOTE: A "split" DYLD Cache header may declare an image, but that image may get loaded at an
	 * address defined by the memory map of a different split header.  This method will only return 
	 * the images that are mapped by "this" header's memory map.
	 * 
	 * 
	 * @return A {@link List} of {@link DyldCacheImage}s mapped by this {@link DyldCacheHeader}
	 */
	public List<DyldCacheImage> getMappedImages() {
		List<DyldCacheImage> images = new ArrayList<>();
		if (imageInfoList.size() > 0) {
			// The old, simple way
			images.addAll(imageInfoList);
		}
		else {
			// The new, split file way.  A split file will have an entry for every image, but
			// not every image will be mapped.
			for (DyldCacheImageTextInfo imageTextInfo : imageTextInfoList) {
				for (DyldCacheMappingInfo mappingInfo : mappingInfoList) {
					if (mappingInfo.contains(imageTextInfo.getAddress())) {
						images.add(imageTextInfo);
						break;
					}
				}
			}
		}
		return images;
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
		
		// headerType 1
		//
		addHeaderField(struct, new ArrayDataType(ASCII, 16, 1), "magic","e.g. \"dyld_v0    i386\"");
		addHeaderField(struct, DWORD, "mappingOffset","file offset to first dyld_cache_mapping_info");
		addHeaderField(struct, DWORD, "mappingCount", "number of dyld_cache_mapping_info entries");
		addHeaderField(struct, DWORD, "imagesOffset", "file offset to first dyld_cache_image_info");
		addHeaderField(struct, DWORD, "imagesCount", "number of dyld_cache_image_info entries");
		addHeaderField(struct, QWORD, "dyldBaseAddress","base address of dyld when cache was built");

		// headerType 2
		//
		addHeaderField(struct, QWORD, "codeSignatureOffset", "file offset of code signature blob");
		addHeaderField(struct, QWORD, "codeSignatureSize","size of code signature blob (zero means to end of file)");
		addHeaderField(struct, QWORD, "slideInfoOffset", "file offset of kernel slid info");
		addHeaderField(struct, QWORD, "slideInfoSize", "size of kernel slid info");

		// headerType 3
		//
		addHeaderField(struct, QWORD, "localSymbolsOffset","file offset of where local symbols are stored");
		addHeaderField(struct, QWORD, "localSymbolsSize", "size of local symbols information");

		// headerType 4
		//
		addHeaderField(struct, new ArrayDataType(BYTE, 16, 1), "uuid","unique value for each shared cache file");

		// headerType 5
		//
		addHeaderField(struct, QWORD, "cacheType", "0 for development, 1 for production");

		// headerType 6
		//
		addHeaderField(struct, DWORD, "branchPoolsOffset","file offset to table of uint64_t pool addresses");
		addHeaderField(struct, DWORD, "branchPoolsCount", "number of uint64_t entries");
		addHeaderField(struct, QWORD, "accelerateInfoAddr","(unslid) address of optimization info");
		addHeaderField(struct, QWORD, "accelerateInfoSize", "size of optimization info");
		addHeaderField(struct, QWORD, "imagesTextOffset","file offset to first dyld_cache_image_text_info");
		addHeaderField(struct, QWORD, "imagesTextCount","number of dyld_cache_image_text_info entries");

		// headerType 7
		//
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
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_mapping_info.");
		}
	}

	private void parseImageInfo(MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (imagesOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD image info...");
		monitor.initialize(imagesCount);
		try {
			reader.setPointerIndex(imagesOffset);
			for (int i = 0; i < imagesCount; ++i) {
				imageInfoList.add(new DyldCacheImageInfo(reader));
				monitor.checkCanceled();
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

	private void parseLocalSymbolsInfo(MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (localSymbolsOffset == 0) {
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
				monitor.checkCanceled();
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
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_image_text_info.");
		}
	}

	private void parseAcceleratorInfo(Program program, AddressSpace space, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		if (accelerateInfoAddr == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD accelerateor info...");
		monitor.initialize(imagesTextCount);
		try {
			Address addr = space.getAddress(accelerateInfoAddr);
			ByteProvider bytes = new MemoryByteProvider(program.getMemory(), addr);
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
				false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
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
					false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
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
					false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
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
			Address addr = fileOffsetToAddr(imagesOffset, program, space);
			for (DyldCacheImageInfo imageInfo : imageInfoList) {
				Data d = DataUtilities.createData(program, addr, imageInfo.toDataType(), -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, imageInfo.getPath());
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
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
					DataUtilities.createData(program, addr, info.toDataType(), -1, false,
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

	private void markupLocalSymbolsInfo(Program program, AddressSpace space, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD local symbols info...");
		monitor.initialize(1);
		try {
			if (localSymbolsInfo != null) {
				Address addr = fileOffsetToAddr(localSymbolsOffset, program, space);
				DataUtilities.createData(program, addr, localSymbolsInfo.toDataType(), -1, false,
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
					Pointer64DataType.dataType.getLength(), false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
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
			if (accelerateInfo != null) {
				Address addr = space.getAddress(accelerateInfoAddr);
				DataUtilities.createData(program, addr, accelerateInfo.toDataType(), -1, false,
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
					false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing()
						.setComment(addr, CodeUnit.EOL_COMMENT, imageTextInfo.getPath());
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to markup dyld_cache_image_text_info.");
		}
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

		// Now check the special memory block that contains bytes that weren't supposed to get
		// mapped in to memory
		AddressSpace fileSpace = program.getAddressFactory().getAddressSpace("FILE");
		if (fileSpace != null) {
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
	public boolean haSlideInfo() {
		if (slideInfoSize != 0) {
			// this is no longer used, but if non-zero, is older format and has slide-info
			return true;
		}
		if (headerType > 6) {
			for (DyldCacheMappingAndSlideInfo info : cacheMappingAndSlideInfoList) {
				if (info.getSlideInfoFileSize() != 0) {
					return true;
				}
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
}
