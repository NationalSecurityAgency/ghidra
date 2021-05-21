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

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.listing.Program;
import ghidra.util.DataConverter;
import ghidra.util.task.TaskMonitor;

public interface OptionalHeader extends StructConverter {

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

	/**
	 * Returns true of this optional header is 64-bit.
	 * @return true of this optional header is 64-bit
	 */
	public boolean is64bit();

	/**
	 * Return the major version number of the linker that built this binary.
	 * @return
	 */
	public byte getMajorLinkerVersion();

	/**
	 * Return the minor version number of the linker that built this binary.
	 * @return
	 */
	public byte getMinorLinkerVersion();

	/**
	 * Return the major version number of the required operating system.
	 * @return
	 */
	public short getMajorOperatingSystemVersion();

	/**
	 * Return the minor version number of the required operating system.
	 * @return
	 */
	public short getMinorOperatingSystemVersion();

	/**
	 * Get the major version number of the image.
	 * @return
	 */
	public short getMajorImageVersion();

	/**
	 * Get the minor version number of the image.
	 * @return
	 */
	public short getMinorImageVersion();

	/**
	 * Get the major version number of the subsystem.
	 */
	public short getMajorSubsystemVersion();

	/**
	 * Get the minor version number of the subsystem.
	 * @return
	 */
	public short getMinorSubsystemVersion();

	/**
	 * This value is reserved, and must be 0
	 */
	public int getWin32VersionValue();

	/**
	 * Get the image file checksum.
	 * @return
	 */
	public int getChecksum();

	/**
	* Get the subsystem that is required to run this image.
	* @return
	*/
	public int getSubsystem();

	/**
	 * Return flags that describe properties of and features of this binary.
	 * @see ghidra.app.util.bin.format.pe.DllCharacteristics
	 * @return
	 */
	public short getDllCharacteristics();

	/**
	 * Return the size of the stack reservation
	 * @return
	 */
	public long getSizeOfStackReserve();

	/**
	 * Return the size of the stack to commit
	 * @return
	 */
	public long getSizeOfStackCommit();

	/**
	 * Return the size of the heap reservation
	 * @return
	 */
	public long getSizeOfHeapReserve();

	/**
	 * Return the size of the heap to commit
	 * @return
	 */
	public long getSizeOfHeapCommit();

	/**
	 * Return the flags passed to the loader. Obsolete.
	 * @return
	 */
	public int getLoaderFlags();

	/**
	 * @return the RVA of the first code byte in the file that will be executed
	 */
	public long getAddressOfEntryPoint();

	/**
	 * @return the preferred load address of this file in memory
	 */
	public long getImageBase();

	public long getOriginalImageBase();

	public boolean wasRebased();

	/**
	 * @return the RVA that would be assigned to the next section following the last section
	 */
	public long getSizeOfImage();

	/**
	 * @see #getSizeOfImage()
	 */
	public void setSizeOfImage(long size);

	/**
	 * @return the combined size of all headers
	 */
	public long getSizeOfHeaders();

	/**
	 * @see #getSizeOfHeaders()
	 */
	public void setSizeOfHeaders(long size);

	/**
	 * Returns the combined total size of all sections with
	 * the <code>IMAGE_SCN_CNT_CODE</code> attribute.
	 * @return the combined total size of all sections with
	 * the <code>IMAGE_SCN_CNT_CODE</code> attribute.
	 */
	public long getSizeOfCode();

	/**
	 * @see #getSizeOfCode()
	 */
	public void setSizeOfCode(long size);

	public long getNumberOfRvaAndSizes();

	/**
	 * Returns the combined size of all initialized data sections.
	 * @return the combined size of all initialized data sections
	 */
	public long getSizeOfInitializedData();

	/**
	 * @see #getSizeOfInitializedData()
	 */
	public void setSizeOfInitializedData(long size);

	/**
	 * Returns the size of all sections with the uninitialized
	 * data attributes.
	 * @return the size of all sections with the uninitialized data attributes
	 */
	public long getSizeOfUninitializedData();

	/**
	 * @see #getSizeOfUninitializedData()
	 */
	public void setSizeOfUninitializedData(long size);

	/**
	 * Returns the RVA of the first byte of code when loaded in memory.
	 * @return the RVA of the first byte of code when loaded in memory
	 */
	public long getBaseOfCode();

	/**
	 * @return the RVA of the first byte of data when loaded into memory
	 */
	public long getBaseOfData();

	/**
	 * This methods tells this optional header to process its data directories.
	 */
	public void processDataDirectories(TaskMonitor monitor) throws IOException;

	/**
	 * Returns the array of data directories.
	 * @return the array of data directories
	 */
	public DataDirectory[] getDataDirectories();

	/**
	 * @return the section alignment
	 */
	public int getSectionAlignment();

	/**
	 * @return the file alignment
	 */
	public int getFileAlignment();

	/**
	 * Writes this optional header to the specified random access file.
	 *
	 * @param raf the random access file
	 * @param dc  the data converter
	 *
	 * @throws IOException
	 */
	public void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException;

	public void validateDataDirectories(Program program);

	/**
	 * @return true if the PE uses predominantly CLI code; otherwise, false.
	 */
	public boolean isCLI() throws IOException;
}
