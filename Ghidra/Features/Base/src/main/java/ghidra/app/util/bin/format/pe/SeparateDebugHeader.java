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
import java.util.ArrayList;
import java.util.List;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser;
import ghidra.util.Conv;
import ghidra.util.Msg;

/**
 * <pre>
 * typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
 *     WORD        Signature;
 *     WORD        Flags;
 *     WORD        Machine;
 *     WORD        Characteristics;
 *     DWORD       TimeDateStamp;
 *     DWORD       CheckSum;
 *     DWORD       ImageBase;
 *     DWORD       SizeOfImage;
 *     DWORD       NumberOfSections;
 *     DWORD       ExportedNamesSize;
 *     DWORD       DebugDirectorySize;
 *     DWORD       SectionAlignment;
 *     DWORD       Reserved[2];
 * } IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;
 * </pre> 
 * 
 * 
 */
public class SeparateDebugHeader implements OffsetValidator {
	/**
	 * The magic number for separate debug files.
	 */
	public final static int IMAGE_SEPARATE_DEBUG_SIGNATURE = 0x4944; //ID
	/**
	 * The magic number for separate debug files on MAC.
	 */
	public final static int IMAGE_SEPARATE_DEBUG_SIGNATURE_MAC = 0x4449; //DI

	private short signature;
	private short flags;
	private short machine;
	private short characteristics;
	private int timeDateStamp;
	private int checkSum;
	private int imageBase;
	private int sizeOfImage;
	private int numberOfSections;
	private int exportedNamesSize;
	private int debugDirectorySize;
	private int sectionAlignment;
	private int[] reserved = new int[2];

	private SectionHeader[] sections;
	private String[] exportedNames;
	private DebugDirectoryParser parser;

	/**
	 * Constructs a new separate debug header using the specified byte provider.
	 * @param bp the byte provider
	 * @throws IOException if an I/O error occurs.
	 */
	public SeparateDebugHeader(GenericFactory factory, ByteProvider bp) throws IOException {
		FactoryBundledWithBinaryReader reader =
			new FactoryBundledWithBinaryReader(factory, bp, true);

		reader.setPointerIndex(0);

		signature = reader.readNextShort();

		if (signature != IMAGE_SEPARATE_DEBUG_SIGNATURE) {
			return;
		}

		flags = reader.readNextShort();
		machine = reader.readNextShort();
		characteristics = reader.readNextShort();
		timeDateStamp = reader.readNextInt();
		checkSum = reader.readNextInt();
		imageBase = reader.readNextInt();
		sizeOfImage = reader.readNextInt();
		numberOfSections = reader.readNextInt();
		exportedNamesSize = reader.readNextInt();
		debugDirectorySize = reader.readNextInt();
		sectionAlignment = reader.readNextInt();
		reserved = reader.readNextIntArray(2);

		if (numberOfSections > NTHeader.MAX_SANE_COUNT) {
			Msg.error(this, "Number of sections " + numberOfSections);
			return;
		}

		long ptr = reader.getPointerIndex();

		sections = new SectionHeader[numberOfSections];
		for (int i = 0; i < numberOfSections; ++i) {
			sections[i] = SectionHeader.readSectionHeader(reader, ptr, -1);
			ptr += SectionHeader.IMAGE_SIZEOF_SECTION_HEADER;
		}

		long tmp = ptr;
		List<String> exportedNameslist = new ArrayList<>();
		while (true) {
			String str = reader.readAsciiString(tmp);
			if (str == null || str.length() == 0) {
				break;
			}
			tmp += str.length() + 1;
			exportedNameslist.add(str);
		}
		exportedNames = new String[exportedNameslist.size()];
		exportedNameslist.toArray(exportedNames);

		ptr += exportedNamesSize;

		parser =
			DebugDirectoryParser.createDebugDirectoryParser(reader, ptr, debugDirectorySize, this);
	}

	/**
	 * Returns the characteristics.
	 * @return the characteristics
	 */
	public short getCharacteristics() {
		return characteristics;
	}

	/**
	 * Returns the check sum.
	 * @return the check sum
	 */
	public int getCheckSum() {
		return checkSum;
	}

	/**
	 * Returns the debug directory size.
	 * @return the debug directory size
	 */
	public int getDebugDirectorySize() {
		return debugDirectorySize;
	}

	/**
	 * Returns the exported names size.
	 * @return the exported names size
	 */
	public int getExportedNamesSize() {
		return exportedNamesSize;
	}

	/**
	 * Returns the flags.
	 * @return the flags
	 */
	public short getFlags() {
		return flags;
	}

	/**
	 * Returns the image base.
	 * @return the image base
	 */
	public int getImageBase() {
		return imageBase;
	}

	/**
	 * Returns the machine type (or processor).
	 * @return the machine type
	 */
	public short getMachine() {
		return machine;
	}

	/**
	 * Returns the machine name (or processor name).
	 * @return the machine name
	 */
	public String getMachineName() {
		return MachineName.getName(machine);
	}

	/**
	 * Returns the number of sections.
	 * @return the number of sections
	 */
	public int getNumberOfSections() {
		return numberOfSections;
	}

	/**
	 * Returns the reserved int array.
	 * @return the reserved int array
	 */
	public int[] getReserved() {
		return reserved;
	}

	/**
	 * Returns the section alignment value.
	 * @return the section alignment value
	 */
	public int getSectionAlignment() {
		return sectionAlignment;
	}

	/**
	 * Returns the signature (or magic number).
	 * @return the signature
	 */
	public short getSignature() {
		return signature;
	}

	/**
	 * Returns the size of the image.
	 * @return the size of the image
	 */
	public int getSizeOfImage() {
		return sizeOfImage;
	}

	/**
	 * Returns the time date stamp.
	 * @return the time date stamp
	 */
	public int getTimeDateStamp() {
		return timeDateStamp;
	}

	/**
	 * Returns the debug directory parser.
	 * @return the debug directory parser
	 */
	public DebugDirectoryParser getParser() {
		return parser;
	}

	@Override
	public boolean checkPointer(long ptr) {
		for (int i = 0; i < sections.length; ++i) {
			long rawSize = sections[i].getSizeOfRawData() & Conv.INT_MASK;
			long rawPtr = sections[i].getPointerToRawData() & Conv.INT_MASK;

			if (ptr >= rawPtr && ptr <= rawPtr + rawSize) { // <= allows data after the last section, which is OK
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean checkRVA(long rva) {
		return (0 <= rva) && (rva <= sizeOfImage);
	}

}
