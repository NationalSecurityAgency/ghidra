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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * See Apple's -- PEFBinaryFormat.h
 * <pre>
 * struct PEFContainerHeader {
 *     OSType  tag1;              //Must contain 'Joy!'.
 *     SType   tag2;              //Must contain 'peff'.  (Yes, with two 'f's.)
 *     OSType  architecture;      //The ISA for code sections.  Constants in CodeFragments.h.
 *     UInt32  formatVersion;     //The physical format version.
 *     UInt32  dateTimeStamp;     //Macintosh format creation/modification stamp.
 *     UInt32  oldDefVersion;     //Old definition version number for the code fragment.
 *     UInt32  oldImpVersion;     //Old implementation version number for the code fragment.
 *     UInt32  currentVersion;    //Current version number for the code fragment.
 *     UInt16  sectionCount;      //Total number of section headers that follow.
 *     UInt16  instSectionCount;  //Number of instantiated sections.
 *     UInt32  reservedA;         //Reserved, must be written as zero
 * };
 * </pre>
 */
public class ContainerHeader implements StructConverter {
	public final static String TAG1 = "Joy!";
	public final static String TAG2 = "peff";

	public final static String ARCHITECTURE_PPC = "pwpc";
	public final static String ARCHITECTURE_68k = "m68k";

	private String  tag1;
	private String  tag2;
	private String  architecture;
	private int     formatVersion;
	private int     dateTimeStamp;
	private int     oldDefVersion;
	private int     oldImpVersion;
	private int     currentVersion;
	private short   sectionCount;
	private short   instSectionCount;
	private int     reservedA;

	private LoaderInfoHeader _loader;
	private List<SectionHeader> _sections = new ArrayList<SectionHeader>();
	private long _sectionIndex;
	private BinaryReader _reader;

	public ContainerHeader(ByteProvider provider) throws IOException, PefException {

		_reader = new BinaryReader(provider, false);

		tag1             = _reader.readNextAsciiString(4);
		tag2             = _reader.readNextAsciiString(4);
		architecture     = _reader.readNextAsciiString(4);
		formatVersion    = _reader.readNextInt();
		dateTimeStamp    = _reader.readNextInt();
		oldDefVersion    = _reader.readNextInt();
		oldImpVersion    = _reader.readNextInt();
		currentVersion   = _reader.readNextInt();
		sectionCount     = _reader.readNextShort();
		instSectionCount = _reader.readNextShort();
		reservedA        = _reader.readNextInt();

		if (!tag1.equals(TAG1) || !tag2.equals(TAG2)) {
			throw new PefException("Invalid PEF file.");
		}
		if (!ARCHITECTURE_68k.equals(architecture) && !ARCHITECTURE_PPC.equals(architecture)) {
			throw new PefException("Invalid architecture specified: "+architecture);
		}

		_sectionIndex = _reader.getPointerIndex();
	}

	public void parse() throws IOException, PefException {
		_reader.setPointerIndex(_sectionIndex);
		for (int i = 0 ; i < sectionCount ; ++i) {
			SectionHeader section = new SectionHeader(_reader);
			if (section.getSectionKind() == SectionKind.Loader) {
				if (_loader != null) {
					throw new PefException("Multple loader sections exist!");
				}
				_loader = new LoaderInfoHeader(_reader, section);
			}
			_sections.add(section);
		}
	}

	/**
	 * Always returns "Joy!"
	 * @return always returns "Joy!"
	 */
	public String getTag1() {
		return tag1;
	}
	/**
	 * Always returns "peff"
	 * @return always returns "peff"
	 */
	public String getTag2() {
		return tag2;
	}
	/**
	 * Returns the architecture for this container.
	 * Either PowerPC CFM or CFm-68k.
	 * @return the architecture for this container
	 */
	public String getArchitecture() {
		return architecture;
	}
	/**
	 * Returns the version of this PEF container.
	 * The current version is 1.
	 * @return the version of this PEF container
	 */
	public int getFormatVersion() {
		return formatVersion;
	}
	/**
	 * Returns the creation date of this PEF container.
	 * The stamp follows the Mac time-measurement scheme.
	 * That is, the number of seconds measured from Jan 1, 1904.
	 * @return the creation date of this PEF container
	 */
	public int getDateTimeStamp() {
		return dateTimeStamp;
	}
	/**
	 * Returns the old CFM version.
	 * @return the old CFM version
	 */
	public int getOldDefVersion() {
		return oldDefVersion;
	}
	/**
	 * Returns the old CFM implementation version.
	 * @return the old CFM implementation version
	 */
	public int getOldImpVersion() {
		return oldImpVersion;
	}
	/**
	 * Returns the current CFM version.
	 * @return the current CFM version
	 */
	public int getCurrentVersion() {
		return currentVersion;
	}
	/**
	 * Returns the total sections in this container.
	 * @return the total sections in this container
	 */
	public short getSectionCount() {
		return sectionCount;
	}
	/**
	 * Returns the number of instantiated sections.
	 * Instantiated sections contain code or data that 
	 * are required for execution.
	 * @return the number of instantiated sections
	 */
	public short getInstantiatedSectionCount() {
		return instSectionCount;
	}
	/**
	 * Reserved field, always returns zero (0).
	 * @return always returns zero (0)
	 */
	public int getReservedA() {
		return reservedA;
	}

	public List<SectionHeader> getSections() {
		return _sections;
	}

	public LoaderInfoHeader getLoader() {
		return _loader;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("ContainerHeader", 0);
		struct.add(STRING, 4, "tag1", null);
		struct.add(STRING, 4, "tag2", null);
		struct.add(STRING, 4, "architecture", null);
		struct.add(DWORD, "formatVersion", null);
		struct.add(new MacintoshTimeStampDataType(), "dateTimeStamp", null);
		struct.add(DWORD, "oldDefVersion", null);
		struct.add(DWORD, "oldImpVersion", null);
		struct.add(DWORD, "currentVersion", null);
		struct.add(WORD, "sectionCount", null);
		struct.add(WORD, "instSectionCount", null);
		struct.add(DWORD, "reservedA", null);
		return struct;
	}

	public long getImageBase() {
		return 0;//TODO is image base always 0?
	}
}
