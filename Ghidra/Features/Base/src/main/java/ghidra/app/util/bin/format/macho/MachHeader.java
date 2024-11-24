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
package ghidra.app.util.bin.format.macho;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a mach_header structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h">EXTERNAL_HEADERS/mach-o/loader.h</a> 
 */
public class MachHeader implements StructConverter {
	private int magic;
	private int cpuType;
	private int cpuSubType;
	private int fileType;
	private int nCmds;
	private int sizeOfCmds;
	private int flags;
	private int reserved;//only used in 64-bit

	private boolean _is32bit;
	private List<LoadCommand> _commands = new ArrayList<>();
	private long _commandIndex;
	private BinaryReader _reader;
	private long _machHeaderStartIndexInProvider;
	private long _machHeaderStartIndex = 0;
	private boolean _parsed = false;

	/**
	 * Returns true if the specified ByteProvider starts with a Mach header magic signature.
	 * 
	 * @param provider {@link ByteProvider} to check
	 * @return boolean true if byte provider starts with a MachHeader
	 */
	public static boolean isMachHeader(ByteProvider provider) {
		try {
			return provider.length() > Integer.BYTES &&
				MachConstants.isMagic(readMagic(provider, 0));
		}
		catch (IOException e) {
			// dont care
		}
		return false;
	}
	
	/**
	 * Creates a new {@link MachHeader}.  Assumes the MachHeader starts at index 0 in the 
	 * ByteProvider.
	 * 
	 * @param provider the ByteProvider
	 * @throws IOException if an I/O error occurs while reading from the ByteProvider
	 * @throws MachException if an invalid MachHeader is detected
	 */
	public MachHeader(ByteProvider provider) throws IOException, MachException {
		this(provider, 0);
	}

	/**
	 * Creates a new {@link MachHeader}. Assumes the MachHeader starts at index 
	 * <i>machHeaderStartIndexInProvider</i> in the ByteProvider.
	 * 
	 * @param provider the ByteProvider
	 * @param machHeaderStartIndexInProvider the index into the ByteProvider where the MachHeader 
	 *   begins
	 * @throws IOException if an I/O error occurs while reading from the ByteProvider
	 * @throws MachException if an invalid MachHeader is detected
	 */
	public MachHeader(ByteProvider provider, long machHeaderStartIndexInProvider)
			throws IOException, MachException {
		this(provider, machHeaderStartIndexInProvider, true);
	}

	/**
	 * Creatse a new {@link MachHeader}.  Assumes the MachHeader starts at index 
	 * <i>machHeaderStartIndexInProvider</i> in the ByteProvider.
	 * 
	 * @param provider the ByteProvider
	 * @param machHeaderStartIndexInProvider the index into the ByteProvider where the MachHeader 
	 *   begins.
	 * @param isRemainingMachoRelativeToStartIndex true if the rest of the macho uses relative 
	 *   indexin (this is common in UBI and kernel cache files); otherwise, false if the rest of the
	 *   file uses absolute indexing from 0 (this is common in DYLD cache files)
	 * @throws IOException if an I/O error occurs while reading from the ByteProvider
	 * @throws MachException if an invalid MachHeader is detected
	 */
	public MachHeader(ByteProvider provider, long machHeaderStartIndexInProvider,
			boolean isRemainingMachoRelativeToStartIndex) throws IOException, MachException {
		magic = readMagic(provider, machHeaderStartIndexInProvider);

		if (!MachConstants.isMagic(magic)) {
			throw new MachException("Invalid Mach-O binary.");
		}

		if (isRemainingMachoRelativeToStartIndex) {
			_machHeaderStartIndex = machHeaderStartIndexInProvider;
		}

		_machHeaderStartIndexInProvider = machHeaderStartIndexInProvider;
		_reader = new BinaryReader(provider, isLittleEndian());
		_reader.setPointerIndex(machHeaderStartIndexInProvider + 4);//skip magic number...

		cpuType = _reader.readNextInt();
		cpuSubType = _reader.readNextInt();
		fileType = _reader.readNextInt();
		nCmds = _reader.readNextInt();
		sizeOfCmds = _reader.readNextInt();
		flags = _reader.readNextInt();

		_is32bit = (cpuType & CpuTypes.CPU_ARCH_ABI64) == 0;

		if (!_is32bit) {
			reserved = _reader.readNextInt();
		}
		_commandIndex = _reader.getPointerIndex();
	}

	/**
	 * Parses this {@link MachHeader}'s {@link LoadCommand load commands}
	 * 
	 * @return This {@link MachHeader}, for convenience
	 * @throws IOException If there was an IO-related error
	 * @throws MachException if the load command is invalid
	 */
	public MachHeader parse() throws IOException, MachException {
		return parse(null);
	}
	
	/**
	 * Parses this {@link MachHeader}'s {@link LoadCommand load commands}
	 * 
	 * @param splitDyldCache The {@link SplitDyldCache} that this header resides in.  Could be null
	 *   if a split DYLD cache is not being used.
	 * @return This {@link MachHeader}, for convenience
	 * @throws IOException If there was an IO-related error
	 * @throws MachException if the load command is invalid
	 */
	public MachHeader parse(SplitDyldCache splitDyldCache) throws IOException, MachException {
		if (_parsed) {
			return this;
		}

		// We must parse segment load commands first, so find and store their indexes separately
		long currentIndex = _commandIndex;
		List<Long> segmentIndexes = new ArrayList<>();
		List<Long> nonSegmentIndexes = new ArrayList<>();
		for (int i = 0; i < nCmds; ++i) {
			_reader.setPointerIndex(currentIndex);
			int type = _reader.readNextInt();
			long size = _reader.readNextUnsignedInt();
			if (type == LoadCommandTypes.LC_SEGMENT || type == LoadCommandTypes.LC_SEGMENT_64) {
				segmentIndexes.add(currentIndex);
			}
			else {
				nonSegmentIndexes.add(currentIndex);
			}
			currentIndex += size;
		}
		List<Long> combinedIndexes = new ArrayList<>();
		combinedIndexes.addAll(segmentIndexes);    // Parse segments first
		combinedIndexes.addAll(nonSegmentIndexes); // Parse everything else second
		for (Long index : combinedIndexes) {
			_reader.setPointerIndex(index);
			LoadCommand lc = LoadCommandFactory.getLoadCommand(_reader, this, splitDyldCache);
			_commands.add(lc);
		}
		sanitizeSegmentSectionNames(getAllSegments());
		_parsed = true;
		return this;
	}

	/**
	 * Parses only this {@link MachHeader}'s {@link SegmentCommand segments}
	 * 
	 * @return A {@link List} of this {@link MachHeader}'s {@link SegmentCommand segments}
	 * @throws IOException If there was an IO-related error
	 */
	public List<SegmentCommand> parseSegments() throws IOException {
		List<SegmentCommand> segments = new ArrayList<>();
		_reader.setPointerIndex(_commandIndex);
		for (int i = 0; i < nCmds; ++i) {
			int type = _reader.peekNextInt();
			if (type == LoadCommandTypes.LC_SEGMENT || type == LoadCommandTypes.LC_SEGMENT_64) {
				segments.add(new SegmentCommand(_reader, is32bit()));
			}
			else {
				type = _reader.readNextInt();
				long size = _reader.readNextUnsignedInt();
				_reader.setPointerIndex(_reader.getPointerIndex() + size - 8);
			}
		}
		sanitizeSegmentSectionNames(segments);
		return segments;
	}

	/**
	 * Parses only this {@link MachHeader}'s {@link LoadCommand}s to check to see if one of the
	 * given type exists
	 * 
	 * @param loadCommandType The type of {@link LoadCommand} to check for
	 * @return True if this {@link MachHeader} contains the given {@link LoadCommand} type
	 * @throws IOException If there was an IO-related error
	 * @see LoadCommandTypes
	 */
	public boolean parseAndCheck(int loadCommandType) throws IOException {
		_reader.setPointerIndex(_commandIndex);
		for (int i = 0; i < nCmds; ++i) {
			int type = _reader.peekNextInt();
			if (type == loadCommandType) {
				return true;
			}
			type = _reader.readNextInt();
			long size = _reader.readNextUnsignedInt();
			_reader.setPointerIndex(_reader.getPointerIndex() + size - 8);

		}
		return false;
	}

	public int getMagic() {
		return magic;
	}

	public int getCpuType() {
		return cpuType;
	}

	public long getImageBase() {
		return 0;
	}

	public int getCpuSubType() {
		return cpuSubType;
	}

	public int getFileType() {
		return fileType;
	}

	public int getNumberOfCommands() {
		return nCmds;
	}

	public int getSizeOfCommands() {
		return sizeOfCmds;
	}

	public int getFlags() {
		return flags;
	}

	public int getReserved() throws MachException {
		if (_is32bit) {
			throw new MachException("Field does not exist for 32 bit Mach-O files.");
		}
		return reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("mach_header", 0);
		struct.add(DWORD, "magic", null);
		struct.add(DWORD, "cputype", null);
		struct.add(DWORD, "cpusubtype", null);
		struct.add(DWORD, "filetype", null);
		struct.add(DWORD, "ncmds", null);
		struct.add(DWORD, "sizeofcmds", null);
		struct.add(DWORD, "flags", null);
		if (!_is32bit) {
			struct.add(DWORD, "reserved", null);
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
	
	/**
	 * Returns the start index that should be used for calculating offsets.
	 * This will be 0 for things such as the dyld shared cache where offsets are
	 * based off the beginning of the file.
	 * 
	 * @return the start index that should be used for calculating offsets
	 */
	public long getStartIndex() {
		return _machHeaderStartIndex;
	}

	/**
	 * Returns the offset of the MachHeader in the ByteProvider
	 * 
	 * @return the offset of the MachHeader in the ByteProvider
	 */
	public long getStartIndexInProvider() {
		return _machHeaderStartIndexInProvider;
	}

	public boolean is32bit() {
		return _is32bit;
	}

	public int getAddressSize() {
		return _is32bit ? 4 : 8;
	}

	public List<SegmentCommand> getAllSegments() {
		return getLoadCommands(SegmentCommand.class);
	}

	public SegmentCommand getSegment(String segmentName) {
		for (SegmentCommand segment : getAllSegments()) {
			if (segment.getSegmentName().equals(segmentName)) {
				return segment;
			}
		}
		return null;
	}

	public Section getSection(String segmentName, String sectionName) {
		SegmentCommand segment = getSegment(segmentName);
		if (segment != null) {
			return segment.getSectionByName(sectionName);
		}
		return null;
	}

	public List<Section> getAllSections() {
		List<Section> tmp = new ArrayList<>();
		for (SegmentCommand segment : getAllSegments()) {
			tmp.addAll(segment.getSections());
		}
		return tmp;
	}

	public List<LoadCommand> getLoadCommands() {
		return _commands;
	}

	public <T> List<T> getLoadCommands(Class<T> classType) {
		List<T> tmp = new ArrayList<>();
		for (LoadCommand command : _commands) {
			if (classType.isAssignableFrom(command.getClass())) {
				tmp.add(classType.cast(command));
			}
		}
		return tmp;
	}

	public <T> T getFirstLoadCommand(Class<T> classType) {
		for (LoadCommand command : _commands) {
			if (classType.isAssignableFrom(command.getClass())) {
				return classType.cast(command);
			}
		}
		return null;
	}

	public boolean isLittleEndian() {//TODO -- if intel it is LE
		return magic == MachConstants.MH_CIGAM || magic == MachConstants.MH_CIGAM_64;
	}

	/**
	 * Gets the size of this {@link MachHeader} in bytes
	 * 
	 * @return The size of this {@link MachHeader} in bytes
	 */
	public long getSize() {
		return _commandIndex - _machHeaderStartIndexInProvider;
	}

	public String getDescription() {//TODO
		StringBuffer buffer = new StringBuffer();
		buffer.append("Magic: 0x" + Integer.toHexString(magic));
		buffer.append('\n');
		buffer.append("CPU Type: " + CpuTypes.getProcessor(cpuType, cpuSubType).toString());
		buffer.append('\n');
		buffer.append("File Type: " + MachHeaderFileTypes.getFileTypeName(fileType));
		buffer.append('\n');
		buffer.append("Flags: 0x" + Integer.toBinaryString(flags));
		buffer.append('\n');
		buffer.append(MachHeaderFlags.getFlags(flags));
		buffer.append('\n');
		return buffer.toString();
	}

	@Override
	public String toString() {
		return getDescription();
	}

	/**
	 * Sanitizes invalid segment/section names so they can be used as memory blocks and program tree
	 * modules.
	 * <p>
	 * There are 3 main cases we have come across that need sanitization:
	 * <ol>
	 *   <li>Segment names have a null character in the middle</li>
	 *   <li>.o files have one segment with a blank name, but the sections refer to more than one
	 *   normal looking segment name</li>
	 *   <li>Some segment and section name are complete garbage bytes</li>
	 * </ol>
	 * 
	 * @param segments A {@link List} of {@link SegmentCommand segments} to sanitize
	 */
	private void sanitizeSegmentSectionNames(List<SegmentCommand> segments) {
		Function<String, Boolean> invalid = s -> s.isBlank() || !Memory.isValidMemoryBlockName(s);
		for (int i = 0; i < segments.size(); i++) {
			SegmentCommand segment = segments.get(i);
			segment.setSegmentName(segment.getSegmentName().replace('\0', '_'));
			if (invalid.apply(segment.getSegmentName())) {
				segment.setSegmentName("__INVALID.%d".formatted(i));
			}
			List<Section> sections = segment.getSections();
			for (int j = 0; j < sections.size(); j++) {
				Section section = sections.get(j);
				section.setSegmentName(section.getSegmentName().replace('\0', '_'));
				section.setSectionName(section.getSectionName().replace('\0', '_'));
				if (invalid.apply(section.getSegmentName())) {
					section.setSegmentName("__INVALID.%d".formatted(i));
				}
				if (invalid.apply(section.getSectionName())) {
					section.setSectionName("__invalid.%d".formatted(j));
				}
			}
		}
	}

	/**
	 * Creates a new Mach Header byte array
	 * 
	 * @param magic The magic
	 * @param cpuType The cpu type
	 * @param cpuSubType The cpu subtype
	 * @param fileType The file type
	 * @param nCmds The number of commands
	 * @param sizeOfCmds The size of the commands
	 * @param flags The flags
	 * @param reserved A reserved value (ignored for 32-bit magic)
	 * @return The new header in byte array form
	 * @throws MachException if an invalid magic value was passed in (see {@link MachConstants})
	 */
	public static byte[] create(int magic, int cpuType, int cpuSubType, int fileType, int nCmds,
			int sizeOfCmds, int flags, int reserved) throws MachException {
		if (!MachConstants.isMagic(magic)) {
			throw new MachException("Invalid magic: 0x%x".formatted(magic));
		}

		DataConverter conv = DataConverter.getInstance(magic == MachConstants.MH_MAGIC);
		boolean is64bit = magic == MachConstants.MH_CIGAM_64 || magic == MachConstants.MH_MAGIC_64;

		byte[] bytes = new byte[is64bit ? 0x20 : 0x1c];
		conv.putInt(bytes, 0x00, magic);
		conv.putInt(bytes, 0x04, cpuType);
		conv.putInt(bytes, 0x08, cpuSubType);
		conv.putInt(bytes, 0x0c, fileType);
		conv.putInt(bytes, 0x10, nCmds);
		conv.putInt(bytes, 0x14, sizeOfCmds);
		conv.putInt(bytes, 0x18, flags);
		if (is64bit) {
			conv.putInt(bytes, 0x1c, reserved);
		}

		return bytes;
	}

	private static int readMagic(ByteProvider provider, long machHeaderStartIndexInProvider)
			throws IOException {
		BinaryReader br = new BinaryReader(provider, false);
		return br.readInt(machHeaderStartIndexInProvider);
	}
}
