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
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the <b><code>IMAGE_NT_HEADERS32</code></b> and
 * IMAGE_NT_HEADERS64 structs as defined in
 * <code>winnt.h</code>.
 * <pre>
 * typedef struct _IMAGE_NT_HEADERS {
 *    DWORD Signature;
 *    IMAGE_FILE_HEADER FileHeader;
 *    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
 * };
 * </pre>
 *
 *
 */
public class NTHeader implements StructConverter, OffsetValidator {
	/**
	 * The size of the NT header signature.
	 */
	public final static int SIZEOF_SIGNATURE = BinaryReader.SIZEOF_INT;
	public final static int MAX_SANE_COUNT = 0x10000;

	private int signature;
	private FileHeader fileHeader;
	private OptionalHeader optionalHeader;
	private BinaryReader reader;
	private int index;
	private boolean parseCliHeaders = false;

	private SectionLayout layout = SectionLayout.FILE;

	/**
	 * Constructs a new NT header.
	 * @param reader the binary reader
	 * @param index the index into the reader to the start of the NT header
	 * @param layout The {@link SectionLayout}
	 * @param parseCliHeaders if true, CLI headers are parsed (if present)
	 * @throws InvalidNTHeaderException if the bytes the specified index
	 * @throws IOException if an IO-related exception occurred
	 * do not constitute an accurate NT header.
	 */
	public NTHeader(BinaryReader reader, int index, SectionLayout layout, boolean parseCliHeaders)
			throws InvalidNTHeaderException, IOException {
		this.reader = reader;
		this.index = index;
		this.layout = layout;
		this.parseCliHeaders = parseCliHeaders;

		parse();
	}

	/**
	 * Returns the name to use when converting into a structure data type.
	 * @return the name to use when converting into a structure data type
	 */
	public String getName() {
		return "IMAGE_NT_HEADERS" + (optionalHeader.is64bit() ? "64" : "32");
	}

	public boolean isRVAResoltionSectionAligned() {
		return layout == SectionLayout.MEMORY;
	}

	/**
	 * Returns the file header.
	 * @return the file header
	 */
	public FileHeader getFileHeader() {
		return fileHeader;
	}

	/**
	 * Returns the optional header.
	 * @return the optional header
	 */
	public OptionalHeader getOptionalHeader() {
		return optionalHeader;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(new ArrayDataType(ASCII, 4, 1), "Signature", null);
		struct.add(fileHeader.toDataType(), "FileHeader", null);
		struct.add(optionalHeader.toDataType(), "OptionalHeader", null);

		struct.setCategoryPath(new CategoryPath("/PE"));

		return struct;
	}

	/**
	 * Converts a relative virtual address (RVA) into a pointer.
	 * 
	 * @param rva the relative virtual address
	 * @return the pointer into binary image, 0 if not valid
	 */
	public int rvaToPointer(int rva) {
		return (int) rvaToPointer(Integer.toUnsignedLong(rva));
	}

	/**
	 * Converts a relative virtual address (RVA) into a pointer.
	
	 * @param rva the relative virtual address
	 * @return the pointer into binary image, -1 if not valid
	 */
	public long rvaToPointer(long rva) {
		SectionHeader[] sections = fileHeader.getSectionHeaders();
		for (SectionHeader section : sections) {
			long sectionVA = Integer.toUnsignedLong(section.getVirtualAddress());
			long vSize = Integer.toUnsignedLong(section.getVirtualSize());
			long rawPtr = Integer.toUnsignedLong(section.getPointerToRawData());
			long rawSize = Integer.toUnsignedLong(section.getSizeOfRawData());

			switch (layout) {
				case MEMORY:
					return rva;
				case FILE:
				default:
					if (rva >= sectionVA && rva < sectionVA + vSize) {
						// NOTE: virtual size is used in the above check because it's already been
						// adjusted for special-case scenarios when the sections were first 
						// processed in FileHeader.java
						long ptr = rva + rawPtr - sectionVA;

						// Make sure the pointer points to actual section file byte, rather than
						// padding bytes
						if (ptr >= rawPtr + rawSize) {
							return -1;
						}

						return ptr;
					}
					break;
			}
		}
		//
		//low alignment mode?
		//
		if (optionalHeader != null) {
			if (optionalHeader.getFileAlignment() == optionalHeader.getSectionAlignment() &&
				optionalHeader.getSectionAlignment() < 800 &&
				optionalHeader.getFileAlignment() > 1) {
				return rva;
			}
		}
		return -1;
	}

	@Override
	public boolean checkPointer(long ptr) {
		SectionHeader[] sections = fileHeader.getSectionHeaders();
		for (SectionHeader section : sections) {
			long virtPtr = Integer.toUnsignedLong(section.getVirtualAddress());
			long virtSize = Integer.toUnsignedLong(section.getVirtualSize());
			long rawSize = Integer.toUnsignedLong(section.getSizeOfRawData());
			long rawPtr = Integer.toUnsignedLong(section.getPointerToRawData());

			long sectionBasePtr = layout == SectionLayout.MEMORY ? virtPtr : rawPtr;
			long sectionSize = layout == SectionLayout.MEMORY ? virtSize : rawSize;

			if (ptr >= sectionBasePtr && ptr <= sectionBasePtr + sectionSize) { // <= allows data after the last section, which is OK
				return true;
			}
		}
		if (optionalHeader != null) {
			if (optionalHeader.getFileAlignment() == optionalHeader.getSectionAlignment()) {
				return checkRVA(ptr);
			}
		}
		return false;
	}

	@Override
	public boolean checkRVA(long rva) {
		if (optionalHeader != null) {
			return (0 <= rva) && (rva <= optionalHeader.getSizeOfImage());
		}
		return true;
	}

	/**
	 * Converts a virtual address (VA) into a pointer.
	 * 
	 * @param va the virtual address
	 * @return the pointer into binary image, 0 if not valid
	 */
	public int vaToPointer(int va) {
		return (int) vaToPointer(Integer.toUnsignedLong(va));
	}

	/**
	 * Converts a virtual address (VA) into a pointer.
	 * 
	 * @param va the virtual address
	 * @return the pointer into binary image, 0 if not valid
	 */
	public long vaToPointer(long va) {
		return rvaToPointer(va - getOptionalHeader().getImageBase());
	}

	private void parse() throws InvalidNTHeaderException, IOException {

		if (index < 0 || index > reader.length()) {
			return;
		}

		int tmpIndex = index;

		try {
			signature = reader.readInt(tmpIndex);
		}
		catch (IndexOutOfBoundsException ioobe) {
			// Handled below
		}

		// if not correct signature, then return...
		if (signature != Constants.IMAGE_NT_SIGNATURE) {
			throw new InvalidNTHeaderException();
		}

		tmpIndex += 4;

		fileHeader = new FileHeader(reader, tmpIndex, this);
		if (fileHeader.getSizeOfOptionalHeader() == 0) {
			Msg.warn(this, "Section headers overlap optional header");
		}
		tmpIndex += FileHeader.IMAGE_SIZEOF_FILE_HEADER;

		optionalHeader = new OptionalHeader(this, reader, tmpIndex);

		// Process symbols.  Allow parsing to continue on failure.
		boolean symbolsProcessed = false;
		try {
			fileHeader.processSymbols();
			symbolsProcessed = true;
		}
		catch (Exception e) {
			Msg.error(this, "Failed to process symbols: " + e.getMessage());
		}

		// Process sections.  Resolving some sections names (i.e., "/21") requires symbols to have
		// been successfully processed.  Resolving is optional though.
		fileHeader.processSections(optionalHeader, symbolsProcessed);
	}

	void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException {

		raf.seek(index);

		raf.write(dc.getBytes(signature));

		fileHeader.writeHeader(raf, dc);

		optionalHeader.writeHeader(raf, dc);

		SectionHeader[] sections = fileHeader.getSectionHeaders();
		for (SectionHeader section : sections) {
			section.writeHeader(raf, dc);
		}
	}

	boolean shouldParseCliHeaders() {
		return parseCliHeaders;
	}
}
