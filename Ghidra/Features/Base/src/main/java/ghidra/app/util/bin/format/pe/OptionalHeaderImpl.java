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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.ImageCor20Header.ImageCor20Flags;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotYetImplementedException;
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
	protected FactoryBundledWithBinaryReader reader;
	protected int startIndex;
	private long startOfDataDirs;

	protected long originalImageBase;
	protected boolean wasRebased;

	static OptionalHeader createOptionalHeader(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader, int startIndex) throws IOException {
		OptionalHeaderImpl optionalHeaderImpl =
			(OptionalHeaderImpl) reader.getFactory().create(OptionalHeaderImpl.class);
		optionalHeaderImpl.initOptionalHeaderImpl(ntHeader, reader, startIndex);
		return optionalHeaderImpl;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public OptionalHeaderImpl() {
	}

	private void initOptionalHeaderImpl(NTHeader ntHeader, FactoryBundledWithBinaryReader reader,
			int startIndex) throws IOException {
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
		switch (magic) {
			case Constants.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
				return false;

			case Constants.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
				return true;
		}
		int characteristics = ntHeader.getFileHeader().getCharacteristics();
		if ((characteristics & FileHeader.IMAGE_FILE_DLL) == FileHeader.IMAGE_FILE_DLL &&
			(characteristics & FileHeader.IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
			Msg.warn(this, "Invalid magic " + magic + " but potentially data-only DLL");
			return false;
		}
		throw new NotYetImplementedException(
			"Optional header of type [" + Integer.toHexString(magic) + "] is not supported");
	}

	@Override
	public long getImageBase() {
		return imageBase;
	}

	@Override
	public long getOriginalImageBase() {
		return originalImageBase;
	}

	@Override
	public long getAddressOfEntryPoint() {
		return Conv.intToLong(addressOfEntryPoint);
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
		return Conv.intToLong(sizeOfInitializedData);
	}

	@Override
	public void setSizeOfInitializedData(long size) {
		this.sizeOfInitializedData = (int) size;
	}

	@Override
	public long getSizeOfUninitializedData() {
		return Conv.intToLong(sizeOfUninitializedData);
	}

	@Override
	public void setSizeOfUninitializedData(long size) {
		this.sizeOfUninitializedData = (int) size;
	}

	@Override
	public long getBaseOfCode() {
		return Conv.intToLong(baseOfCode);
	}

	@Override
	public long getBaseOfData() {
		return Conv.intToLong(baseOfData);
	}

	@Override
	public long getSizeOfImage() {
		return Conv.intToLong(sizeOfImage);
	}

	@Override
	public void setSizeOfImage(long size) {
		this.sizeOfImage = (int) size;
	}

	@Override
	public long getSizeOfHeaders() {
		return Conv.intToLong(sizeOfHeaders);
	}

	@Override
	public void setSizeOfHeaders(long size) {
		this.sizeOfHeaders = (int) size;
	}

	@Override
	public long getNumberOfRvaAndSizes() {
		return Conv.intToLong(numberOfRvaAndSizes);
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
		dataDirectory = new DataDirectory[numberOfRvaAndSizes];
		if (numberOfRvaAndSizes == 0) {
			return;
		}

		int ndata = 0;
		monitor.setMessage("Parsing exports...");
		try {
			dataDirectory[ndata] = ExportDataDirectory.createExportDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] = ImportDataDirectory.createImportDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				ResourceDataDirectory.createResourceDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				ExceptionDataDirectory.createExceptionDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				SecurityDataDirectory.createSecurityDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				BaseRelocationDataDirectory.createBaseRelocationDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] = DebugDataDirectory.createDebugDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				ArchitectureDataDirectory.createArchitectureDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				GlobalPointerDataDirectory.createGlobalPointerDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] = TLSDataDirectory.createTLSDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				LoadConfigDataDirectory.createLoadConfigDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				BoundImportDataDirectory.createBoundImportDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				ImportAddressTableDataDirectory.createImportAddressTableDataDirectory(ntHeader,
					reader);
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
			dataDirectory[ndata] =
				DelayImportDataDirectory.createDelayImportDataDirectory(ntHeader, reader);
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
			dataDirectory[ndata] =
				COMDescriptorDataDirectory.createCOMDescriptorDataDirectory(ntHeader, reader);
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
			if (imageBase <= 0) {
				Msg.warn(this, "Non-standard image base: 0x" + Long.toHexString(imageBase));
				originalImageBase = imageBase;
				imageBase = 0x10000;
				wasRebased = true;
			}
		}
		else {
			baseOfData = reader.readNextInt();
			int imgBase = reader.readNextInt();
			imageBase = imgBase & Conv.INT_MASK;
			if (imgBase <= 0) {
				Msg.warn(this, "Non-standard image base " + Integer.toHexString(imgBase));
				originalImageBase = imageBase;
				imageBase = 0x10000;
				wasRebased = true;
			}
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
			sizeOfStackReserve = reader.readNextInt() & Conv.INT_MASK;
			sizeOfStackCommit = reader.readNextInt() & Conv.INT_MASK;
			sizeOfHeapReserve = reader.readNextInt() & Conv.INT_MASK;
			sizeOfHeapCommit = reader.readNextInt() & Conv.INT_MASK;
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
	public boolean wasRebased() {
		return wasRebased;
	}

	@Override
	public boolean isCLI() throws IOException {
		long origPointerIndex = reader.getPointerIndex();

		reader.setPointerIndex(startOfDataDirs + (DataDirectory.IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY *
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));

		ImageCor20Header cor20 =
			COMDescriptorDataDirectory.createCOMDescriptorDataDirectory(ntHeader,
				reader).getHeader();

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
