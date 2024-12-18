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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;
import java.io.RandomAccessFile;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.ImageCor20Header.ImageCor20Flags;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * <pre>
 * typedef struct _IMAGE_OPTIONAL_HEADER {
 *     WORD    Magic;									// MANDATORY
 *     BYTE    MajorLinkerVersion;
 *     BYTE    MinorLinkerVersion;
 *     DWORD   SizeOfCode;
 *     DWORD   SizeOfInitializedData;
 *     DWORD   SizeOfUninitializedData;
 *     DWORD   AddressOfEntryPoint;						// MANDATORY
 *     DWORD   BaseOfCode;
 *     DWORD   BaseOfData;
 *     DWORD   ImageBase;								// MANDATORY
 *     DWORD   SectionAlignment;						// MANDATORY
 *     DWORD   FileAlignment;							// MANDATORY
 *     WORD    MajorOperatingSystemVersion;				// MANDATORY
 *     WORD    MinorOperatingSystemVersion;
 *     WORD    MajorImageVersion;
 *     WORD    MinorImageVersion;
 *     WORD    MajorSubsystemVersion;
 *     WORD    MinorSubsystemVersion;
 *     DWORD   Win32VersionValue;
 *     DWORD   SizeOfImage;								// MANDATORY
 *     DWORD   SizeOfHeaders;							// MANDATORY
 *     DWORD   CheckSum;
 *     WORD    Subsystem;								// MANDATORY
 *     WORD    DllCharacteristics;
 *     DWORD   SizeOfStackReserve;
 *     DWORD   SizeOfStackCommit;
 *     DWORD   SizeOfHeapReserve;
 *     DWORD   SizeOfHeapCommit;
 *     DWORD   LoaderFlags;
 *     DWORD   NumberOfRvaAndSizes;						// USED
 *     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
 * };
 * </pre>
 * 
 * <pre>
 * typedef struct _IMAGE_OPTIONAL_HEADER64 {
 *     WORD        Magic;
 *     BYTE        MajorLinkerVersion;
 *     BYTE        MinorLinkerVersion;
 *     DWORD       SizeOfCode;
 *     DWORD       SizeOfInitializedData;
 *     DWORD       SizeOfUninitializedData;
 *     DWORD       AddressOfEntryPoint;
 *     DWORD       BaseOfCode;
 *     ULONGLONG   ImageBase;
 *     DWORD       SectionAlignment;
 *     DWORD       FileAlignment;
 *     WORD        MajorOperatingSystemVersion;
 *     WORD        MinorOperatingSystemVersion;
 *     WORD        MajorImageVersion;
 *     WORD        MinorImageVersion;
 *     WORD        MajorSubsystemVersion;
 *     WORD        MinorSubsystemVersion;
 *     DWORD       Win32VersionValue;
 *     DWORD       SizeOfImage;
 *     DWORD       SizeOfHeaders;
 *     DWORD       CheckSum;
 *     WORD        Subsystem;
 *     WORD        DllCharacteristics;
 *     ULONGLONG   SizeOfStackReserve;
 *     ULONGLONG   SizeOfStackCommit;
 *     ULONGLONG   SizeOfHeapReserve;
 *     ULONGLONG   SizeOfHeapCommit;
 *     DWORD       LoaderFlags;
 *     DWORD       NumberOfRvaAndSizes;
 *     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
 * };
 * </pre>
 * 
 * 
 */
public class OptionalHeaderImpl implements OptionalHeader {
	protected short magic;
	protected byte majorLinkerVersion;
	protected byte minorLinkerVersion;
	protected int sizeOfCode;
	protected int sizeOfInitializedData;
	protected int sizeOfUninitializedData;
	protected int addressOfEntryPoint;
	protected int baseOfCode;
	protected int baseOfData;
	protected long imageBase;
	protected int sectionAlignment;
	protected int fileAlignment;
	protected short majorOperatingSystemVersion;
	protected short minorOperatingSystemVersion;
	protected short majorImageVersion;
	protected short minorImageVersion;
	protected short majorSubsystemVersion;
	protected short minorSubsystemVersion;
	protected int win32VersionValue;
	protected int sizeOfImage;
	protected int sizeOfHeaders;
	protected int checkSum;
	protected short subsystem;
	protected short dllCharacteristics;
	protected long sizeOfStackReserve;
	protected long sizeOfStackCommit;
	protected long sizeOfHeapReserve;
	protected long sizeOfHeapCommit;
	protected int loaderFlags;
	protected int numberOfRvaAndSizes;
	protected DataDirectory[] dataDirectory;

	protected NTHeader ntHeader;
	protected BinaryReader reader;
	protected int startIndex;
	private long startOfDataDirs;

	OptionalHeaderImpl(NTHeader ntHeader, BinaryReader reader, int startIndex) throws IOException {
		this.ntHeader = ntHeader;
		this.reader = reader;
		this.startIndex = startIndex;

		parse();
	}

	private String getName() {
		return "IMAGE_OPTIONAL_HEADER" + (is64bit() ? "64" : "32");
	}

	@Override
	public boolean is64bit() {
		return magic == Constants.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	}

	@Override
	public long getImageBase() {
		return imageBase;
	}

	@Override
	public long getAddressOfEntryPoint() {
		return Integer.toUnsignedLong(addressOfEntryPoint);
	}

	@Override
	public long getSizeOfCode() {
		return sizeOfCode;
	}

	@Override
	public void setSizeOfCode(long size) {
		this.sizeOfCode = (int) size;
	}

	@Override
	public long getSizeOfInitializedData() {
		return Integer.toUnsignedLong(sizeOfInitializedData);
	}

	@Override
	public void setSizeOfInitializedData(long size) {
		this.sizeOfInitializedData = (int) size;
	}

	@Override
	public long getSizeOfUninitializedData() {
		return Integer.toUnsignedLong(sizeOfUninitializedData);
	}

	@Override
	public void setSizeOfUninitializedData(long size) {
		this.sizeOfUninitializedData = (int) size;
	}

	@Override
	public long getBaseOfCode() {
		return Integer.toUnsignedLong(baseOfCode);
	}

	@Override
	public long getBaseOfData() {
		return Integer.toUnsignedLong(baseOfData);
	}

	@Override
	public long getSizeOfImage() {
		return Integer.toUnsignedLong(sizeOfImage);
	}

	@Override
	public void setSizeOfImage(long size) {
		this.sizeOfImage = (int) size;
	}

	@Override
	public long getSizeOfHeaders() {
		return Integer.toUnsignedLong(sizeOfHeaders);
	}

	@Override
	public void setSizeOfHeaders(long size) {
		this.sizeOfHeaders = (int) size;
	}

	@Override
	public long getNumberOfRvaAndSizes() {
		return Integer.toUnsignedLong(numberOfRvaAndSizes);
	}

	@Override
	public short getMajorOperatingSystemVersion() {
		return majorOperatingSystemVersion;
	}

	@Override
	public short getMinorOperatingSystemVersion() {
		return minorOperatingSystemVersion;
	}

	@Override
	public void processDataDirectories(TaskMonitor monitor) throws IOException {
		reader.setPointerIndex(startOfDataDirs);

		dataDirectory = new DataDirectory[numberOfRvaAndSizes];
		if (numberOfRvaAndSizes == 0) {
			return;
		}

		int ndata = 0;
		monitor.setMessage("Parsing exports...");
		try {
			dataDirectory[ndata] = new ExportDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing imports...");
		try {
			dataDirectory[ndata] = new ImportDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing resources...");
		try {
			dataDirectory[ndata] = new ResourceDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing exceptions...");
		try {
			dataDirectory[ndata] = new ExceptionDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing security...");
		try {
			dataDirectory[ndata] = new SecurityDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing relocations...");
		try {
			dataDirectory[ndata] = new BaseRelocationDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing debug information...");
		try {
			dataDirectory[ndata] = new DebugDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing architecture...");
		try {
			dataDirectory[ndata] = new ArchitectureDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing global pointer...");
		try {
			dataDirectory[ndata] = new GlobalPointerDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing TLS data...");
		try {
			dataDirectory[ndata] = new TLSDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing load config data...");
		try {
			dataDirectory[ndata] = new LoadConfigDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (ndata++ == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing bound imports...");
		try {
			dataDirectory[ndata] = new BoundImportDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing import address table...");
		try {
			dataDirectory[ndata] = new ImportAddressTableDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing delay imports...");
		try {
			dataDirectory[ndata] = new DelayImportDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		monitor.setMessage("Parsing COM descriptors...");
		try {
			dataDirectory[ndata] = new COMDescriptorDataDirectory(ntHeader, reader);
		}
		catch (RuntimeException re) {
			if (PortableExecutable.DEBUG) {
				throw re;
			}
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		dataDirectory[ndata] = null;
	}

	@Override
	public DataDirectory[] getDataDirectories() {
		return dataDirectory;
	}

	@Override
	public int getSectionAlignment() {
		return sectionAlignment;
	}

	@Override
	public int getFileAlignment() {
		return fileAlignment;
	}

	protected void parse() throws IOException {
		reader.setPointerIndex(startIndex);

		magic = reader.readNextShort();
		if (magic != Constants.IMAGE_ROM_OPTIONAL_HDR_MAGIC &&
			magic != Constants.IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
			magic != Constants.IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			Msg.warn(this, "Unsupported magic value: 0x%x. Assuming 32-bit.".formatted(magic));
		}
		majorLinkerVersion = reader.readNextByte();
		minorLinkerVersion = reader.readNextByte();
		sizeOfCode = reader.readNextInt();
		sizeOfInitializedData = reader.readNextInt();
		sizeOfUninitializedData = reader.readNextInt();
		addressOfEntryPoint = reader.readNextInt();
		// NB: 0 or negative addressOfEntryPoint is legal
		if (addressOfEntryPoint < 0) {
			Msg.warn(this, "Negative entry point " + Integer.toHexString(addressOfEntryPoint));
		}
		if (addressOfEntryPoint == 0) {
			int characteristics = ntHeader.getFileHeader().getCharacteristics();
			if ((characteristics & FileHeader.IMAGE_FILE_DLL) == 0) {
				Msg.warn(this, "Zero entry point for non-DLL");
			}
		}
		baseOfCode = reader.readNextInt();

		if (is64bit()) {
			baseOfData = -1;//not used
			imageBase = reader.readNextLong();
		}
		else {
			baseOfData = reader.readNextInt();
			imageBase = Integer.toUnsignedLong(reader.readNextInt());
		}

		sectionAlignment = reader.readNextInt();
		fileAlignment = reader.readNextInt();
		if (fileAlignment < 0x200) {
			Msg.warn(this, "Unusual file alignment: 0x" + Integer.toHexString(fileAlignment));
		}
		majorOperatingSystemVersion = reader.readNextShort();
		minorOperatingSystemVersion = reader.readNextShort();
		majorImageVersion = reader.readNextShort();
		minorImageVersion = reader.readNextShort();
		majorSubsystemVersion = reader.readNextShort();
		minorSubsystemVersion = reader.readNextShort();
		win32VersionValue = reader.readNextInt();
		sizeOfImage = reader.readNextInt();
		sizeOfHeaders = reader.readNextInt();
		if (sizeOfHeaders >= sizeOfImage) {
			Msg.warn(this, "Size of headers >= size of image: forced load");
		}
		checkSum = reader.readNextInt();
		subsystem = reader.readNextShort();
		dllCharacteristics = reader.readNextShort();

		if (is64bit()) {
			sizeOfStackReserve = reader.readNextLong();
			sizeOfStackCommit = reader.readNextLong();
			sizeOfHeapReserve = reader.readNextLong();
			sizeOfHeapCommit = reader.readNextLong();
		}
		else {
			sizeOfStackReserve = reader.readNextUnsignedInt();
			sizeOfStackCommit = reader.readNextUnsignedInt();
			sizeOfHeapReserve = reader.readNextUnsignedInt();
			sizeOfHeapCommit = reader.readNextUnsignedInt();
		}

		loaderFlags = reader.readNextInt();
		numberOfRvaAndSizes = reader.readNextInt();

		if (numberOfRvaAndSizes != IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
			Msg.warn(this, "Non-standard # of data directories: " + numberOfRvaAndSizes);
			if (numberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES || numberOfRvaAndSizes < 0) {
				Msg.warn(this,
					"Forcing # of data directories to: " + IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
				numberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			}
		}

		startOfDataDirs = reader.getPointerIndex();
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType ddstruct = new StructureDataType(DataDirectory.TITLE, 0);
		ddstruct.add(IBO32, "VirtualAddress", null);
		ddstruct.add(DWORD, "Size", null);
		ddstruct.setCategoryPath(new CategoryPath("/PE"));

		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(WORD, "Magic", null);
		struct.add(BYTE, "MajorLinkerVersion", null);
		struct.add(BYTE, "MinorLinkerVersion", null);
		struct.add(DWORD, "SizeOfCode", null);
		struct.add(DWORD, "SizeOfInitializedData", null);
		struct.add(DWORD, "SizeOfUninitializedData", null);
		struct.add(IBO32, "AddressOfEntryPoint", null);
		struct.add(IBO32, "BaseOfCode", null);
		if (is64bit()) {
			//BaseOfData does not exist in 64 bit
			struct.add(new Pointer64DataType(), "ImageBase", null);
		}
		else {
			struct.add(IBO32, "BaseOfData", null);
			struct.add(new Pointer32DataType(), "ImageBase", null);
		}
		struct.add(DWORD, "SectionAlignment", null);
		struct.add(DWORD, "FileAlignment", null);
		struct.add(WORD, "MajorOperatingSystemVersion", null);
		struct.add(WORD, "MinorOperatingSystemVersion", null);
		struct.add(WORD, "MajorImageVersion", null);
		struct.add(WORD, "MinorImageVersion", null);
		struct.add(WORD, "MajorSubsystemVersion", null);
		struct.add(WORD, "MinorSubsystemVersion", null);
		struct.add(DWORD, "Win32VersionValue", null);
		struct.add(DWORD, "SizeOfImage", null);
		struct.add(DWORD, "SizeOfHeaders", null);
		struct.add(DWORD, "CheckSum", null);
		struct.add(WORD, "Subsystem", null);
		struct.add(WORD, "DllCharacteristics", null);
		if (is64bit()) {
			struct.add(QWORD, "SizeOfStackReserve", null);
			struct.add(QWORD, "SizeOfStackCommit", null);
			struct.add(QWORD, "SizeOfHeapReserve", null);
			struct.add(QWORD, "SizeOfHeapCommit", null);
		}
		else {
			struct.add(DWORD, "SizeOfStackReserve", null);
			struct.add(DWORD, "SizeOfStackCommit", null);
			struct.add(DWORD, "SizeOfHeapReserve", null);
			struct.add(DWORD, "SizeOfHeapCommit", null);
		}
		struct.add(DWORD, "LoaderFlags", null);
		struct.add(DWORD, "NumberOfRvaAndSizes", null);
		struct.add(
			new ArrayDataType(ddstruct, numberOfRvaAndSizes, ddstruct.getLength()),
			"DataDirectory", null);

		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	@Override
	public void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.write(dc.getBytes(magic));
		raf.write(new byte[] { majorLinkerVersion });
		raf.write(new byte[] { minorLinkerVersion });
		raf.write(dc.getBytes(sizeOfCode));
		raf.write(dc.getBytes(sizeOfInitializedData));
		raf.write(dc.getBytes(sizeOfUninitializedData));
		raf.write(dc.getBytes(addressOfEntryPoint));
		raf.write(dc.getBytes(baseOfCode));
		if (is64bit()) {
			//BaseOfData does not exist in 64 bit
			raf.write(dc.getBytes(imageBase));
		}
		else {
			raf.write(dc.getBytes(baseOfData));
			raf.write(dc.getBytes((int) imageBase));
		}
		raf.write(dc.getBytes(sectionAlignment));
		raf.write(dc.getBytes(fileAlignment));
		raf.write(dc.getBytes(majorOperatingSystemVersion));
		raf.write(dc.getBytes(minorOperatingSystemVersion));
		raf.write(dc.getBytes(majorImageVersion));
		raf.write(dc.getBytes(minorImageVersion));
		raf.write(dc.getBytes(majorSubsystemVersion));
		raf.write(dc.getBytes(minorSubsystemVersion));
		raf.write(dc.getBytes(win32VersionValue));
		raf.write(dc.getBytes(sizeOfImage));
		raf.write(dc.getBytes(sizeOfHeaders));
		raf.write(dc.getBytes(checkSum));
		raf.write(dc.getBytes(subsystem));
		raf.write(dc.getBytes(dllCharacteristics));
		if (is64bit()) {
			raf.write(dc.getBytes(sizeOfStackReserve));
			raf.write(dc.getBytes(sizeOfStackCommit));
			raf.write(dc.getBytes(sizeOfHeapReserve));
			raf.write(dc.getBytes(sizeOfHeapCommit));
		}
		else {
			raf.write(dc.getBytes((int) sizeOfStackReserve));
			raf.write(dc.getBytes((int) sizeOfStackCommit));
			raf.write(dc.getBytes((int) sizeOfHeapReserve));
			raf.write(dc.getBytes((int) sizeOfHeapCommit));
		}
		raf.write(dc.getBytes(loaderFlags));
		raf.write(dc.getBytes(numberOfRvaAndSizes));

		//the last one is null ...
		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
			if (dataDirectory[i] != null) {
				raf.write(dc.getBytes(dataDirectory[i].getVirtualAddress()));
				raf.write(dc.getBytes(dataDirectory[i].getSize()));
			}
			else {
				raf.write(dc.getBytes(0));
				raf.write(dc.getBytes(0));
			}
		}
	}

	@Override
	public void validateDataDirectories(Program program) {
		Memory memory = program.getMemory();
		int sizeint = Integer.SIZE / 8;
		Address addr = program.getImageBase().add(startOfDataDirs);
		for (int i = 0; i < numberOfRvaAndSizes; i++) {
			try {
				int virtualAddress = memory.getInt(addr, false);
				addr = addr.add(sizeint);
				int size = memory.getInt(addr, false);
				addr = addr.add(sizeint);
				if (dataDirectory[i] != null && dataDirectory[i].hasParsedCorrectly()) {
					if (dataDirectory[i].getVirtualAddress() != virtualAddress) {
						Msg.warn(this,
							"Correcting dataDirectory[" + i + "] va:" +
								Integer.toHexString(dataDirectory[i].getVirtualAddress()) + "->" +
								Integer.toHexString(virtualAddress));
						dataDirectory[i].setVirtualAddress(virtualAddress);
					}
					if (dataDirectory[i].getSize() != size) {
						Msg.warn(this,
							"Correcting dataDirectory[" + i + "] sz:" +
								Integer.toHexString(dataDirectory[i].getSize()) + "->" +
								Integer.toHexString(size));
						dataDirectory[i].setSize(size);
					}
				}
			}
			catch (MemoryAccessException e) {
				e.printStackTrace();
			}
			catch (AddressOutOfBoundsException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public boolean isCLI() throws IOException {
		long origPointerIndex = reader.getPointerIndex();

		reader.setPointerIndex(startOfDataDirs + (DataDirectory.IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY *
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));

		ImageCor20Header cor20 = new COMDescriptorDataDirectory(ntHeader, reader).getHeader();

		reader.setPointerIndex(origPointerIndex);

		if (cor20 == null) {
			return false;
		}

		boolean intermediateLanguageOnly = (cor20.getFlags() &
			ImageCor20Flags.COMIMAGE_FLAGS_ILONLY) == ImageCor20Flags.COMIMAGE_FLAGS_ILONLY;

		return intermediateLanguageOnly && cor20.getManagedNativeHeader().getVirtualAddress() == 0;
	}

	@Override
	public byte getMajorLinkerVersion() {
		return majorLinkerVersion;
	}

	@Override
	public byte getMinorLinkerVersion() {
		return minorLinkerVersion;
	}

	@Override
	public short getMajorImageVersion() {
		return majorImageVersion;
	}

	@Override
	public short getMinorImageVersion() {
		return minorImageVersion;
	}

	@Override
	public short getMajorSubsystemVersion() {
		return majorSubsystemVersion;
	}

	@Override
	public short getMinorSubsystemVersion() {
		return minorSubsystemVersion;
	}

	@Override
	public int getWin32VersionValue() {
		return win32VersionValue;
	}

	@Override
	public int getChecksum() {
		return checkSum;
	}

	@Override
	public int getSubsystem() {
		return subsystem;
	}

	@Override
	public short getDllCharacteristics() {
		return dllCharacteristics;
	}

	@Override
	public long getSizeOfStackReserve() {
		return sizeOfStackReserve;
	}

	@Override
	public long getSizeOfStackCommit() {
		return sizeOfStackCommit;
	}

	@Override
	public long getSizeOfHeapReserve() {
		return sizeOfHeapReserve;
	}

	@Override
	public long getSizeOfHeapCommit() {
		return sizeOfHeapCommit;
	}

	@Override
	public int getLoaderFlags() {
		return loaderFlags;
	}
}
