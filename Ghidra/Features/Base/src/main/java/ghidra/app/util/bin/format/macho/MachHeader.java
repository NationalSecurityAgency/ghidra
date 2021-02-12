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

import generic.continues.GenericFactory;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a mach_header structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
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
	private FactoryBundledWithBinaryReader _reader;
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
	 * Assumes the MachHeader starts at index 0 in the ByteProvider.
	 * @param provider the ByteProvider
	 * @throws IOException if an I/O error occurs while reading from the ByteProvider
	 * @throws MachException if an invalid MachHeader is detected
	 */
	public static MachHeader createMachHeader(GenericFactory factory, ByteProvider provider)
			throws IOException, MachException {
		return createMachHeader(factory, provider, 0);
	}

	/**
	 * Assumes the MachHeader starts at index <i>machHeaderStartIndexInProvider</i> in the ByteProvider.
	 * @param provider the ByteProvider
	 * @param machHeaderStartIndexInProvider the index into the ByteProvider where the MachHeader begins.
	 * @throws IOException if an I/O error occurs while reading from the ByteProvider
	 * @throws MachException if an invalid MachHeader is detected
	 */
	public static MachHeader createMachHeader(GenericFactory factory, ByteProvider provider,
			long machHeaderStartIndexInProvider) throws IOException, MachException {
		MachHeader machHeader = (MachHeader) factory.create(MachHeader.class);
		machHeader.initMachHeader(factory, provider, machHeaderStartIndexInProvider, true);
		return machHeader;
	}

	/**
	 * Assumes the MachHeader starts at index <i>machHeaderStartIndexInProvider</i> in the ByteProvider.
	 * @param provider the ByteProvider
	 * @param machHeaderStartIndexInProvider the index into the ByteProvider where the MachHeader begins.
	 * @param isRemainingMachoRelativeToStartIndex TRUE if the rest of the macho uses relative indexing. This is common in UBI and kernel cache files.
	 *                                             FALSE if the rest of the file uses absolute indexing from 0. This is common in DYLD cache files.
	 * @throws IOException if an I/O error occurs while reading from the ByteProvider
	 * @throws MachException if an invalid MachHeader is detected
	 */
	public static MachHeader createMachHeader(GenericFactory factory, ByteProvider provider,
			long machHeaderStartIndexInProvider, boolean isRemainingMachoRelativeToStartIndex)
			throws IOException, MachException {
		MachHeader machHeader = (MachHeader) factory.create(MachHeader.class);
		machHeader.initMachHeader(factory, provider, machHeaderStartIndexInProvider,
			isRemainingMachoRelativeToStartIndex);
		return machHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public MachHeader() {
	}

	private void initMachHeader(GenericFactory factory, ByteProvider provider,
			long machHeaderStartIndexInProvider, boolean isRemainingMachoRelativeToStartIndex)
			throws IOException, MachException {
		magic = readMagic(provider, machHeaderStartIndexInProvider);

		if (!MachConstants.isMagic(magic)) {
			throw new MachException("Invalid Mach-O binary.");
		}

		if (isRemainingMachoRelativeToStartIndex) {
			_machHeaderStartIndex = machHeaderStartIndexInProvider;
		}

		_machHeaderStartIndexInProvider = machHeaderStartIndexInProvider;
		_reader = new FactoryBundledWithBinaryReader(factory, provider, isLittleEndian());
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

	public void parse() throws IOException, MachException {
		if (_parsed) {
			return;
		}
		for (int i = 0; i < nCmds; ++i) {
			_reader.setPointerIndex(_commandIndex);
			LoadCommand lc = LoadCommandTypes.getLoadCommand(_reader, this);
			_commands.add(lc);
			_commandIndex += lc.getCommandSize();
		}
		_parsed = true;
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
	 */
	public long getStartIndex() {
		return _machHeaderStartIndex;
	}

	/**
	 * Returns offset of MachHeader in the ByteProvider
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

	private static int readMagic(ByteProvider provider, long machHeaderStartIndexInProvider)
			throws IOException {
		BinaryReader br = new BinaryReader(provider, false);
		return br.readInt(machHeaderStartIndexInProvider);
	}
}
