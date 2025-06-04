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
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.ImageCor20Header.ImageCor20Flags;
import ghidra.app.util.importer.MessageLog;
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
 * <pre>{@code
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
 * 
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
 * }</pre>
 */
public class OptionalHeader implements StructConverter {

	/**
	 * ASLR with 64 bit address space.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;

	/**
	 * The DLL can be relocated at load time.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;

	/**
	 * Code integrity checks are forced.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080;

	/**
	 * The image is compatible with data execution prevention (DEP)
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;

	/**
	 * The image is isolation aware, but should not be isolated.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200;

	/**
	 * The image does not use structured exception handling (SEH).
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400;

	/**
	 * Do not bind the image.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800;

	/**
	 * Image should execute in an AppContainer.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000;

	/**
	 * A WDM driver.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000;

	/**
	 * Image supports Control Flow Guard.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000;

	/**
	 * The image is terminal server aware.
	 */
	public final static int IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000;

	/**
	 * The count of data directories in the optional header.
	 */
	public final static byte IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

	/**
	 * Export directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
	/**
	 * Import directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
	/**
	 * Resource directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
	/**
	 * Exception directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
	/**
	 * Security directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
	/**
	 * Base Relocation Table directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
	/**
	 * Debug directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
	/**
	 * Architecture Specific Data directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
	/**
	 * Global Pointer directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;//RVA of GP
	/**
	 * TLS directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_TLS = 9;
	/**
	 * Load Configuration directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
	/**
	 * Bound Import directory  index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
	/**
	 * Import Address Table directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_IAT = 12;
	/**
	 * Delay Load Import Descriptors directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
	/**
	 * COM Runtime Descriptor directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
	/**
	 * New name for the COM Descriptor directory index
	 */
	public final static byte IMAGE_DIRECTORY_ENTRY_COMHEADER = 14;

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

	OptionalHeader(NTHeader ntHeader, BinaryReader reader, int startIndex) throws IOException {
		this.ntHeader = ntHeader;
		this.reader = reader;
		this.startIndex = startIndex;

		parse();
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
	 * This methods tells this optional header to process its data directories.
	 * 
	 * @param log The log
	 * @param monitor The monitor
	 */
	public void processDataDirectories(MessageLog log, TaskMonitor monitor) {
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
		catch (IOException e) {
			log.appendMsg(ExportDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(ImportDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(ResourceDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(ExceptionDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(SecurityDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(BaseRelocationDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(DebugDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(ArchitectureDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(GlobalPointerDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(GlobalPointerDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(LoadConfigDataDirectory.class.getSimpleName(), e.getMessage());
		}
		if (++ndata == numberOfRvaAndSizes) {
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
		catch (IOException e) {
			log.appendMsg(BoundImportDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(ImportAddressTableDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(DelayImportDataDirectory.class.getSimpleName(), e.getMessage());
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
		catch (IOException e) {
			log.appendMsg(COMDescriptorDataDirectory.class.getSimpleName(), e.getMessage());
		}
		if (++ndata == numberOfRvaAndSizes) {
			return;
		}

		dataDirectory[ndata] = null;
	}

	/**
	 * {@return  true of this optional header is 64-bit.}
	 */
	public boolean is64bit() {
		return magic == Constants.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	}

	/**
	 * {@return the major version number of the linker that built this binary.}
	 */
	public byte getMajorLinkerVersion() {
		return majorLinkerVersion;
	}

	/**
	 * {@return the minor version number of the linker that built this binary.}
	 */
	public byte getMinorLinkerVersion() {
		return minorLinkerVersion;
	}

	/**
	 * {@return the combined total size of all sections with IMAGE_SCN_CNT_CODE attribute.}
	 */
	public long getSizeOfCode() {
		return sizeOfCode;
	}

	/**
	 * Sets the combined total size of all sections with the IMAGE_SCN_CNT_CODE attribute.
	 * 
	 * @param size The size to set
	 */
	public void setSizeOfCode(long size) {
		this.sizeOfCode = (int) size;
	}

	/**
	 * {@return the combined size of all initialized data sections.}
	 */
	public long getSizeOfInitializedData() {
		return Integer.toUnsignedLong(sizeOfInitializedData);
	}

	/**
	 * Sets the combined size of all initialized data sections}
	 * 
	 * @param size The size to set
	 */
	public void setSizeOfInitializedData(long size) {
		this.sizeOfInitializedData = (int) size;
	}

	/**
	 * {@return the size of all sections with the uninitialized data attributes.}
	 */
	public long getSizeOfUninitializedData() {
		return Integer.toUnsignedLong(sizeOfUninitializedData);
	}

	/**
	 * Sets the size of all sections with the uninitialized data attributes.}
	 * 
	 * @param size The size to set
	 */
	public void setSizeOfUninitializedData(long size) {
		this.sizeOfUninitializedData = (int) size;
	}

	/**
	 * {@return the RVA of the first code byte in the file that will be executed}
	 */
	public long getAddressOfEntryPoint() {
		return Integer.toUnsignedLong(addressOfEntryPoint);
	}

	/**
	 * {@return the RVA of the first byte of code when loaded in memory.}
	 */
	public long getBaseOfCode() {
		return Integer.toUnsignedLong(baseOfCode);
	}

	/**
	 * {@return the RVA of the first byte of data when loaded into memory.}
	 */
	public long getBaseOfData() {
		return Integer.toUnsignedLong(baseOfData);
	}

	/**
	 * {@return the preferred load address of this file in memory}
	 */
	public long getImageBase() {
		return imageBase;
	}

	/**
	 * {@return the section alignment}
	 */
	public int getSectionAlignment() {
		return sectionAlignment;
	}

	/**
	 * {@return the file alignment}
	 */
	public int getFileAlignment() {
		return fileAlignment;
	}

	/**
	 * {@return the major version number of the required operating system.}
	 */
	public short getMajorOperatingSystemVersion() {
		return majorOperatingSystemVersion;
	}

	/**
	 * {@return the minor version number of the required operating system.}
	 */
	public short getMinorOperatingSystemVersion() {
		return minorOperatingSystemVersion;
	}

	/**
	 * {@return the major version number of the image.}
	 */
	public short getMajorImageVersion() {
		return majorImageVersion;
	}

	/**
	 * {@return the minor version number of the image.}
	 */
	public short getMinorImageVersion() {
		return minorImageVersion;
	}

	/**
	 * {@return the major version number of the subsystem.}
	 */
	public short getMajorSubsystemVersion() {
		return majorSubsystemVersion;
	}

	/**
	 * {@return the minor version number of the subsystem.}
	 */
	public short getMinorSubsystemVersion() {
		return minorSubsystemVersion;
	}

	/**
	 * {@return the reserved value, which must be 0}
	 */
	public int getWin32VersionValue() {
		return win32VersionValue;
	}

	/**
	 * {@return the RVA that would be assigned to the next section following the last section}
	 */
	public long getSizeOfImage() {
		return Integer.toUnsignedLong(sizeOfImage);
	}

	/**
	 * Sets the RVA that would be assigned to the next section following the last section
	 * 
	 * @param size The size to set
	 */
	public void setSizeOfImage(long size) {
		this.sizeOfImage = (int) size;
	}

	/**
	 * {@return the combined size of all headers}
	 */
	public long getSizeOfHeaders() {
		return Integer.toUnsignedLong(sizeOfHeaders);
	}

	/**
	 * Sets the combined size of all headers
	 * 
	 * @param size The size to set
	 */
	public void setSizeOfHeaders(long size) {
		this.sizeOfHeaders = (int) size;
	}

	/**
	 * {@return the image file checksum.}
	 */
	public int getChecksum() {
		return checkSum;
	}

	/**
	* {@return the subsystem that is required to run this image.}
	*/
	public int getSubsystem() {
		return subsystem;
	}

	/**
	 * {@return the flags that describe properties of and features of this binary.}
	 * @see ghidra.app.util.bin.format.pe.DllCharacteristics
	 */
	public short getDllCharacteristics() {
		return dllCharacteristics;
	}

	/**
	 * {@return the size of the stack reservation}
	 */
	public long getSizeOfStackReserve() {
		return sizeOfStackReserve;
	}

	/**
	 * {@return the size of the stack to commit}
	 */
	public long getSizeOfStackCommit() {
		return sizeOfStackCommit;
	}

	/**
	 * {@return the size of the heap reservation}
	 */
	public long getSizeOfHeapReserve() {
		return sizeOfHeapReserve;
	}

	/**
	 * {@return the size of the heap to commit}
	 */
	public long getSizeOfHeapCommit() {
		return sizeOfHeapCommit;
	}

	/**
	 * {@return the flags passed to the loader. Obsolete.}
	 */
	public int getLoaderFlags() {
		return loaderFlags;
	}

	/**
	 * {@return the number of data-directory entries in the remainder of the optional header.}
	 */
	public long getNumberOfRvaAndSizes() {
		return Integer.toUnsignedLong(numberOfRvaAndSizes);
	}

	/**
	 * {@return the array of data directories.}
	 */
	public DataDirectory[] getDataDirectories() {
		return dataDirectory;
	}

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

	/**
	 * Writes this optional header to the specified random access file.
	 *
	 * @param raf the random access file
	 * @param dc  the data converter
	 *
	 * @throws IOException if an IO-related error occurred
	 */
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
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				Msg.error(this, "Problem validating data directories", e);
			}
		}
	}

	/**
	 * {@return true if the PE uses predominantly CLI code; otherwise, false.}
	 * 
	 * @throws IOException if an IO-related error occurred
	 */
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

	private String getName() {
		return "IMAGE_OPTIONAL_HEADER" + (is64bit() ? "64" : "32");
	}
}
