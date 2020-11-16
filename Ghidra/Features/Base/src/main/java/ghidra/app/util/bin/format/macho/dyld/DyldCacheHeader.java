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
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
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

	private int headerType;
	private BinaryReader reader;
	private long baseAddress;
	private List<DyldCacheMappingInfo> mappingInfoList;
	private List<DyldCacheImageInfo> imageInfoList;
	private DyldCacheSlideInfoCommon slideInfo;
	private DyldCacheLocalSymbolsInfo localSymbolsInfo;
	private List<Long> branchPoolList;
	private DyldCacheAccelerateInfo accelerateInfo;
	private List<DyldCacheImageTextInfo> imageTextInfoList;
	private DyldArchitecture architecture;

	/**
	 * Create a new {@link DyldCacheHeader}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD cache header
	 * @throws IOException if there was an IO-related problem creating the DYLD cache header
	 */
	public DyldCacheHeader(BinaryReader reader) throws IOException {
		this.reader = reader;

		// ------ HEADER 1 ---------
		headerType = 1; // https://opensource.apple.com/source/dyld/dyld-95.3/launch-cache/dyld_cache_format.h.auto.html
		magic = reader.readNextByteArray(16);
		mappingOffset = reader.readNextInt();
		mappingCount = reader.readNextInt();
		imagesOffset = reader.readNextInt();
		imagesCount = reader.readNextInt();
		dyldBaseAddress = reader.readNextLong();

		// ------ HEADER 2 ---------
		if (mappingOffset > 0x28) {
			headerType = 2; // https://opensource.apple.com/source/dyld/dyld-195.5/launch-cache/dyld_cache_format.h.auto.html
			codeSignatureOffset = reader.readNextLong();
			codeSignatureSize = reader.readNextLong();
			slideInfoOffset = reader.readNextLong();
			slideInfoSize = reader.readNextLong();
		}

		// ------ HEADER 3 ---------
		if (mappingOffset > 0x48) {
			headerType = 3; // No header file for this version (without the following UUID), but there are images of this version
			localSymbolsOffset = reader.readNextLong();
			localSymbolsSize = reader.readNextLong();
		}

		// ------ HEADER 4 ---------
		if (mappingOffset > 0x58) {
			headerType = 4; // https://opensource.apple.com/source/dyld/dyld-239.3/launch-cache/dyld_cache_format.h.auto.html
			uuid = reader.readNextByteArray(16);
		}

		// ------ HEADER 5 ---------
		if (mappingOffset > 0x68) {
			headerType = 5; // https://opensource.apple.com/source/dyld/dyld-360.14/launch-cache/dyld_cache_format.h.auto.html
			cacheType = reader.readNextLong();
		}

		// ------ HEADER 6 ---------
		if (mappingOffset > 0x70) {
			headerType = 6; // https://opensource.apple.com/source/dyld/dyld-421.1/launch-cache/dyld_cache_format.h.auto.html
			branchPoolsOffset = reader.readNextInt();
			branchPoolsCount = reader.readNextInt();
			accelerateInfoAddr = reader.readNextLong();
			accelerateInfoSize = reader.readNextLong();
			imagesTextOffset = reader.readNextLong();
			imagesTextCount = reader.readNextLong();
		}

		baseAddress = reader.readLong(mappingOffset);
		architecture = DyldArchitecture.getArchitecture(new String(magic).trim());

		mappingInfoList = new ArrayList<>(mappingCount);
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
		if (headerType >= 2) {
			parseSlideInfo(log, monitor);
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
	 * Gets the {@link List} of {@link DyldCacheImageInfo}s. Requires header to have been parsed.
	 * 
	 * @return The {@link List} of {@link DyldCacheImageInfo}s
	 */
	public List<DyldCacheImageInfo> getImageInfos() {
		return imageInfoList;
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
	 * Gets the {@link DyldCacheSlideInfoCommon}.
	 * 
	 * @return the {@link DyldCacheSlideInfoCommon}.  Common, or particular version
	 */
	public DyldCacheSlideInfoCommon getSlideInfo() {
		return slideInfo;
	}	

	/**
	 * @return slideInfoOffset
	 */
	public long getSlideInfoOffset() {
		return slideInfoOffset;
	}

	/**
	 * @return slideInfoSize
	 */
	public long getSlideInfoSize() {
		return slideInfoSize;
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
		if (headerType >= 1) {
			struct.add(new ArrayDataType(ASCII, 16, 1), "magic", "e.g. \"dyld_v0    i386\"");
			struct.add(DWORD, "mappingOffset", "file offset to first dyld_cache_mapping_info");
			struct.add(DWORD, "mappingCount", "number of dyld_cache_mapping_info entries");
			struct.add(DWORD, "imagesOffset", "file offset to first dyld_cache_image_info");
			struct.add(DWORD, "imagesCount", "number of dyld_cache_image_info entries");
			struct.add(QWORD, "dyldBaseAddress", "base address of dyld when cache was built");
		}
		if (headerType >= 2) {
			struct.add(QWORD, "codeSignatureOffset", "file offset of code signature blob");
			struct.add(QWORD, "codeSignatureSize",
				"size of code signature blob (zero means to end of file)");
			struct.add(QWORD, "slideInfoOffset", "file offset of kernel slid info");
			struct.add(QWORD, "slideInfoSize", "size of kernel slid info");
		}
		if (headerType >= 3) {
			struct.add(QWORD, "localSymbolsOffset",
				"file offset of where local symbols are stored");
			struct.add(QWORD, "localSymbolsSize", "size of local symbols information");
		}
		if (headerType >= 4) {
			struct.add(new ArrayDataType(BYTE, 16, 1), "uuid",
				"unique value for each shared cache file");
		}
		if (headerType >= 5) {
			struct.add(QWORD, "cacheType", "0 for development, 1 for production");
		}
		if (headerType >= 6) {
			struct.add(DWORD, "branchPoolsOffset",
				"file offset to table of uint64_t pool addresses");
			struct.add(DWORD, "branchPoolsCount", "number of uint64_t entries");
			struct.add(QWORD, "accelerateInfoAddr", "(unslid) address of optimization info");
			struct.add(QWORD, "accelerateInfoSize", "size of optimization info");
			struct.add(QWORD, "imagesTextOffset",
				"file offset to first dyld_cache_image_text_info");
			struct.add(QWORD, "imagesTextCount", "number of dyld_cache_image_text_info entries");
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
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

	private void parseSlideInfo(MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (slideInfoOffset == 0) {
			return;
		}
		monitor.setMessage("Parsing DYLD slide info...");
		monitor.initialize(1);
		try {
			reader.setPointerIndex(slideInfoOffset);
			slideInfo = new DyldCacheSlideInfoCommon(reader);
			reader.setPointerIndex(slideInfoOffset);
			switch (slideInfo.getVersion()) {
				case 1:
					slideInfo = new DyldCacheSlideInfo1(reader);
					break;
				case 2:
					slideInfo = new DyldCacheSlideInfo2(reader);
					break;
				case 3:
					slideInfo = new DyldCacheSlideInfo3(reader);
					break;
				default:
					throw new IOException();
			}
			monitor.incrementProgress(1);
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_slide_info.");
		}
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
			DataUtilities.createData(program, program.getImageBase(), toDataType(), -1, false,
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
			program.getListing().setComment(fileOffsetToAddr(codeSignatureOffset, program, space),
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
			if (slideInfo != null) {
				Address addr = fileOffsetToAddr(slideInfoOffset, program, space);
				DataUtilities.createData(program, addr, slideInfo.toDataType(), -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
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
				program.getListing().setComment(addr, CodeUnit.EOL_COMMENT,
					imageTextInfo.getPath());
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
}
