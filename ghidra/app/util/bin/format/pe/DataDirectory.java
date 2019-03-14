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
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * An abstract base class to represent the
 * <code>IMAGE_DATA_DIRECTORY</code>
 * data structure defined in <b><code>winnt.h</code></b>.
 * <pre>
 * typedef struct _IMAGE_DATA_DIRECTORY {
 *     DWORD   VirtualAddress;
 *     DWORD   Size;
 * } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY; {
 * </pre>
 *
 *
 */
public abstract class DataDirectory implements StructConverter, PeMarkupable {
	/**
	 * The name to use when converting into a structure data type.
	 */
	protected final static String TITLE = "IMAGE_DATA_DIRECTORY";

	/**
	 * The size of the data directory, in bytes.
	 */
	public final static byte IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY = 8;

	protected NTHeader ntHeader;
	protected FactoryBundledWithBinaryReader reader;
	protected int virtualAddress;
	protected int size;
	protected boolean hasParsed = false;

	protected void processDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
			throws IOException {
		this.ntHeader = ntHeader;
		this.reader = reader;

		virtualAddress = reader.readNextInt();
		size = reader.readNextInt();

		if (size < 0 || !ntHeader.checkRVA(virtualAddress)) {
			if (size != 0) {
				Msg.warn(this,
					"DataDirectory RVA outside of image (RVA: 0x" +
						Integer.toHexString(virtualAddress) + ", Size: 0x" +
						Integer.toHexString(size) + ").  Could be a file-only data directory.");
				size = 0;
			}
			return;
		}
		hasParsed = parse();
	}

	public abstract String getDirectoryName();

	/**
	 * Parses this data directory.
	 *
	 * @return True if parsing completed successfully; otherwise, false.
	 * @throws IOException If there was an IO problem while parsing.
	 */
	public abstract boolean parse() throws IOException;

	protected long va(long va, boolean isBinary) {
		if (isBinary) {
			long ptr = ntHeader.rvaToPointer(va);
			if (ptr < 0 && virtualAddress > 0) { //directory does not appear inside a loadable section
				return va;
			}
			return ptr;
		}

		long new_va = va + ntHeader.getOptionalHeader().getImageBase();
		// make sure didn't wrap
		if (ntHeader.getOptionalHeader().is64bit()) {
			return new_va;
		}
		return (new_va & 0xffffffffL);
	}

	protected void createTerminatedString(Program program, Address addr, boolean label,
			MessageLog log) {
		PeUtils.createData(program, addr, new TerminatedStringDataType(), log);
	}

	protected void createDirectoryBookmark(Program program, Address addr) {
		program.getBookmarkManager().setBookmark(addr, BookmarkType.INFO, "PE Header",
			getDirectoryName());
	}

	protected void setBookmark(Program prog, Address addr, String comment) {
		prog.getBookmarkManager().setBookmark(addr, BookmarkType.INFO, "PE Header", comment);
	}

	protected void setPlateComment(Program prog, Address addr, String comment) {
		prog.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, comment);
	}

	protected void setEolComment(Program prog, Address addr, String comment) {
		prog.getListing().setComment(addr, CodeUnit.EOL_COMMENT, comment);
	}

	protected void setPreComment(Program prog, Address addr, String comment) {
		prog.getListing().setComment(addr, CodeUnit.PRE_COMMENT, comment);
	}

	/**
	 * Creates a fragment with the given name (if it does not already exist).
	 * Move the address range into the fragment.
	 * Note: the end address is not inclusive!
	 */
	protected boolean createFragment(Program program, String fragmentName, Address start,
			Address end) {
		try {
			ProgramModule module = program.getListing().getDefaultRootModule();
			ProgramFragment fragment = findFragment(module, fragmentName);
			if (fragment == null) {
				fragment = module.createFragment(fragmentName);
			}
			fragment.move(start, end.subtract(1));
			return true;
		}
		catch (Exception e) {
		}
		return false;
	}

	private ProgramFragment findFragment(ProgramModule module, String fragmentName) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (group.getName().equals(fragmentName)) {
				return (ProgramFragment) group;
			}
		}
		return null;
	}

	/**
	 * Returns the relative virtual address of this data directory.
	 * @return the relative virtual address of this data directory
	 */
	public int getVirtualAddress() {
		return virtualAddress;
	}

	/**
	 * Sets the relative virtual address of this data directory.
	 * @param addr the new relative virtual address
	 */
	public void setVirtualAddress(int addr) {
		this.virtualAddress = addr;
	}

	/**
	 * Returns the size of this data directory.
	 * @return the size of this data directory
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Sets the size of this data directory.
	 * @param size the new size of this data directory
	 */
	public void setSize(int size) {
		this.size = size;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "VirtualAddress: 0x" + Integer.toHexString(virtualAddress) + " " + "Size: " + size +
			" bytes";
	}

	/**
	 * Converts the relative virtual address of this data directory
	 * into a file pointer.
	 * @return the file pointer
	 */
	int rvaToPointer() {
		return ntHeader.rvaToPointer(virtualAddress);
	}

	/**
	 * Returns true if this data directory is contained inside of a section.
	 * If true, that means that the section is loaded into memory
	 * at runtime.
	 * @return true if this data directory is contained inside of a section
	 */
	boolean isContainedInSection() {
		return rvaToPointer() != getVirtualAddress();
	}

	/**
	 * This method should return a datatype representing the data stored
	 * in this directory.
	 */
	@Override
	public abstract DataType toDataType() throws DuplicateNameException, IOException;

	/**
	 * Directories that are not contained inside of sections
	 * should override this method to write their bytes into the
	 * specified file.
	 * @param raf        the random access file used for output
	 * @param dc         the data converter for endianness
	 * @param template   the original unadulterated PE
	 * @throws IOException if an I/O error occurs
	 */
	public void writeBytes(RandomAccessFile raf, DataConverter dc, PortableExecutable template)
			throws IOException {
	}

	public boolean hasParsedCorrectly() {
		return hasParsed;
	}

	public int getPointer() {
		if (virtualAddress == 0) {
			return -1;
		}
		int ptr = ntHeader.rvaToPointer(getVirtualAddress());
		if (ptr < 0) {
			Msg.error(this, "Invalid file index for " + Integer.toHexString(getVirtualAddress()));
		}
		return ptr;
	}

}
