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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.Objects;

/**
 * Image Section Header information, as part of {@link DebugData} structures within
 *  {@link PdbNewDebugInfo} of {@link AbstractPdb} types.  Contains section information;
 *  an older set of section information seems to be located in {@link SegmentMapDescription},
 *  which might be used for {@link PdbOldDebugInfo} types, but we do not yet have data to
 *  confirm this.
 */
public class ImageSectionHeader {

	private AbstractPdb pdb;

	private String name;
	// TODO:
	// unionPAVS: DWORD (unsigned 32-bit). Either Physical Address of Virtual Size--not sure
	//  what to key off of to interpret one over the other.  Guess that it has to do with
	//  VirtualAddress--perhaps a value of 0x00000000 or 0xffffffff.
	// See the to-do below (in dump()) regarding unionPAVS.
	private long unionPAVS;
	private long virtualAddress; // DWORD (unsigned 32-bit)
	private long rawDataSize; // DWORD (unsigned 32-bit)
	private long rawDataPointer; // DWORD (unsigned 32-bit)
	private long relocationsPointer; // DWORD (unsigned 32-bit)
	private long lineNumbersPointer; // DWORD (unsigned 32-bit)
	private int numRelocations; // WORD (unsigned 16-bit)
	private int numLineNumbers; // WORD (unsigned 16-bit)
	private long characteristics; // DWORD (unsigned 32-bit)

	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 */
	public ImageSectionHeader(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Parse the values of this class.
	 * @param reader the {@link PdbByteReader} from which to parse the values.
	 * @throws PdbException upon no enough data to parse.
	 */
	public void parse(PdbByteReader reader) throws PdbException {
		if (reader.numRemaining() < 40) {
			throw new PdbException("Not enough data for ImageSectionHeader");
		}
		PdbByteReader nameReader = reader.getSubPdbByteReader(8);
		name = nameReader.parseNullTerminatedString(pdb.getPdbReaderOptions().getOneByteCharset());
		unionPAVS = reader.parseUnsignedIntVal();
		virtualAddress = reader.parseUnsignedIntVal();
		rawDataSize = reader.parseUnsignedIntVal();
		rawDataPointer = reader.parseUnsignedIntVal();
		relocationsPointer = reader.parseUnsignedIntVal();
		lineNumbersPointer = reader.parseUnsignedIntVal();
		numRelocations = reader.parseUnsignedShortVal();
		numLineNumbers = reader.parseUnsignedShortVal();
		characteristics = reader.parseUnsignedIntVal();
	}

	/**
	 * Returns the {@link ImageSectionHeader} name.
	 * @return the name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the {@link ImageSectionHeader} unionPAVS, which is either Physical Address or
	 * Virtual Size.
	 * @return the unionPAVS.
	 */
	public long getUnionPAVS() {
		return unionPAVS;
	}

	/**
	 * Returns the {@link ImageSectionHeader} virtualAddress.
	 * @return the virtualAddress.
	 */
	public long getVirtualAddress() {
		return virtualAddress;
	}

	/**
	 * Returns the {@link ImageSectionHeader} rawDataSize.
	 * @return the rawDataSize.
	 */
	public long getRawDataSize() {
		return rawDataSize;
	}

	/**
	 * Returns the {@link ImageSectionHeader} rawDataPointer.
	 * @return the rawDataPointer.
	 */
	public long getRawDataPointer() {
		return rawDataPointer;
	}

	/**
	 * Returns the {@link ImageSectionHeader} relocationsPointer.
	 * @return the relocationsPointer.
	 */
	public long getRelocationsPointer() {
		return relocationsPointer;
	}

	/**
	 * Returns the {@link ImageSectionHeader} lineNumbersPointer.
	 * @return the lineNumbersPointer.
	 */
	public long getLineNumbersPointer() {
		return lineNumbersPointer;
	}

	/**
	 * Returns the {@link ImageSectionHeader} numRelocations.
	 * @return the numRelocations.
	 */
	public int getNumRelocations() {
		return numRelocations;
	}

	/**
	 * Returns the {@link ImageSectionHeader} numLineNumbers.
	 * @return the numLineNumbers.
	 */
	public int getNumLineNumbers() {
		return numLineNumbers;
	}

	/**
	 * Returns the {@link ImageSectionHeader} characteristics.
	 * @return the characteristics.
	 */
	public long getCharacteristics() {
		return characteristics;
	}

	/**
	 * Dumps the {@link ImageSectionHeader}.  This package-protected method is for
	 *  debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @param sectionNum the section number to include in the output.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	void dump(Writer writer, int sectionNum) throws IOException {
		writer.write("ImageSectionHeader------------------------------------------\n");
		writer.write(String.format("Section Number: %04X\n", sectionNum));
		writer.write(String.format("name: %s\n", name));
		// TODO:  See the to-do above regarding unionPAVS.
		writer.write(String.format("unionPAVS: 0X%08X\n", unionPAVS));
		writer.write(String.format("virtualAddress: 0X%08X\n", virtualAddress));
		writer.write(String.format("rawDataSize: 0X%08X\n", rawDataSize));
		writer.write(String.format("rawDataPointer: 0X%08X\n", rawDataPointer));
		writer.write(String.format("relocationsPointer: 0X%08X\n", relocationsPointer));
		writer.write(String.format("lineNumbersPointer: 0X%08X\n", lineNumbersPointer));
		writer.write(String.format("numRelocations: 0X%04X\n", numRelocations));
		writer.write(String.format("numLineNumbers: 0X%04X\n", numLineNumbers));
		writer.write(String.format("characteristics: 0X%08X\n", characteristics));
		writer.write("End ImageSectionHeader--------------------------------------\n");
	}
}
