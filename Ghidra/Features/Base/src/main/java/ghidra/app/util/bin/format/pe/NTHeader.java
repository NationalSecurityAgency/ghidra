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
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitorAdapter;

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
	private FactoryBundledWithBinaryReader reader;
	private int index;
	private boolean advancedProcess = true;
	private boolean parseCliHeaders = false;

	private SectionLayout layout = SectionLayout.FILE;

	/**
	 * Constructs a new NT header.
	 * @param reader the binary reader
	 * @param index the index into the reader to the start of the NT header
	 * @param advancedProcess if true, information rafside of the base header will be processed
	 * @param parseCliHeaders if true, CLI headers are parsed (if present)
	 * @throws InvalidNTHeaderException if the bytes the specified index
	 * do not constitute an accurate NT header.
	 */
	public static NTHeader createNTHeader(FactoryBundledWithBinaryReader reader, int index,
			SectionLayout layout, boolean advancedProcess, boolean parseCliHeaders)
			throws InvalidNTHeaderException, IOException {
		NTHeader ntHeader = (NTHeader) reader.getFactory().create(NTHeader.class);
		ntHeader.initNTHeader(reader, index, layout, advancedProcess, parseCliHeaders);
		return ntHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public NTHeader() {
	}

	private void initNTHeader(FactoryBundledWithBinaryReader reader, int index,
			SectionLayout layout, boolean advancedProcess, boolean parseCliHeaders)
			throws InvalidNTHeaderException, IOException {
		this.reader = reader;
		this.index = index;
		this.layout = layout;
		this.advancedProcess = advancedProcess;
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
	 * @see #rvaToPointer(long)
	 */
	public int rvaToPointer(int rva) {
		return (int) rvaToPointer(rva & Conv.INT_MASK);
	}

	/**
	 * @param rva the relative virtual address
	 * @return the pointer into binary image, 0 if not valid
	 */
	public long rvaToPointer(long rva) {
		SectionHeader[] sections = fileHeader.getSectionHeaders();
		for (SectionHeader section : sections) {
			long sectionVA = section.getVirtualAddress() & Conv.INT_MASK;
			long rawSize = section.getSizeOfRawData() & Conv.INT_MASK;
			long rawPtr = section.getPointerToRawData() & Conv.INT_MASK;

			switch (layout) {
				case MEMORY:
					return rva;
				case FILE:
				default:
					if (rva >= sectionVA && rva < sectionVA + rawSize) {
						return rva + rawPtr - sectionVA;
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
			long virtPtr = section.getVirtualAddress() & Conv.INT_MASK;
			long virtSize = section.getVirtualSize() & Conv.INT_MASK;
			long rawSize = section.getSizeOfRawData() & Conv.INT_MASK;
			long rawPtr = section.getPointerToRawData() & Conv.INT_MASK;

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
	 * @see #vaToPointer(long)
	 */
	public int vaToPointer(int va) {
		return (int) vaToPointer(va & Conv.INT_MASK);
	}

	/**
	 * @param va the virtual address
	 * @return the pointer into binary image, 0 if not valid
	 */
	public long vaToPointer(long va) {
		return rvaToPointer(va - getOptionalHeader().getImageBase());
	}

	/**
	 * @throws InvalidNTHeaderException
	 * @throws IOException
	 */
	private void parse() throws InvalidNTHeaderException, IOException {

		if (index < 0 || index > reader.length()) {
			return;
		}

		int tmpIndex = index;

		try {
			signature = reader.readInt(tmpIndex);
		}
		catch (IndexOutOfBoundsException ioobe) {
		}

		// if not correct signature, then return...
		if (signature != Constants.IMAGE_NT_SIGNATURE) {
			throw new InvalidNTHeaderException();
		}

		tmpIndex += 4;

		fileHeader = FileHeader.createFileHeader(reader, tmpIndex, this);
		if (fileHeader.getSizeOfOptionalHeader() == 0) {
			Msg.warn(this, "Section headers overlap optional header");
		}
		tmpIndex += FileHeader.IMAGE_SIZEOF_FILE_HEADER;

		try {
			optionalHeader = OptionalHeaderImpl.createOptionalHeader(this, reader, tmpIndex);
		}
		catch (NotYetImplementedException e) {//TODO
			Msg.error(this, "Unexpected Exception: " + e.getMessage());
			return;
		}

		fileHeader.processSections(optionalHeader);
		fileHeader.processSymbols();
		if ((fileHeader.getMachine() &
			FileHeader.IMAGE_FILE_MACHINE_MASK) == FileHeader.IMAGE_FILE_MACHINE_AMD64) {
			fileHeader.processImageRuntimeFunctionEntries();
		}

		if (advancedProcess) {
			optionalHeader.processDataDirectories(TaskMonitorAdapter.DUMMY_MONITOR);
		}
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
