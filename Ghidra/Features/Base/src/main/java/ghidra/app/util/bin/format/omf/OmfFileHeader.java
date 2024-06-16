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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.task.TaskMonitor;

public class OmfFileHeader extends OmfRecord {

	private String objectName;		// Name of the object module
	private String libModuleName = null;	// Name of the module (within a library)
	private String translator = null;		// Usually the compiler/linker used to produce this object
	private boolean isLittleEndian;
	private ArrayList<String> nameList = new ArrayList<String>();	// Indexable List of segment, group, ... names
	private ArrayList<OmfSegmentHeader> segments = new ArrayList<OmfSegmentHeader>();
	private ArrayList<OmfGroupRecord> groups = new ArrayList<OmfGroupRecord>();
	private ArrayList<OmfExternalSymbol> externsymbols = new ArrayList<OmfExternalSymbol>();
	private ArrayList<OmfSymbolRecord> symbols = new ArrayList<OmfSymbolRecord>();
	private ArrayList<OmfFixupRecord> fixup = new ArrayList<OmfFixupRecord>();
	private ArrayList<OmfSegmentHeader> extraSeg = null;		// Holds implied segments that don't have official header record
	//	private OmfModuleEnd endModule = null;
	private boolean format16bit;

	public OmfFileHeader(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		objectName = readString(reader);			// This is usually the source code filename
		readCheckSumByte(reader);
		isLittleEndian = reader.isLittleEndian();
	}

	/**
	 * This is usually the original source filename
	 * @return the name
	 */
	public String getName() {
		return objectName;
	}

	/**
	 * The name of the object module (within a library)
	 * @return the name
	 */
	public String getLibraryModuleName() {
		return libModuleName;
	}

	/**
	 * @return the string identifying the architecture this object was compiled for
	 */
	public String getMachineName() {
		return format16bit ? "16bit" : "32bit";
	}

	/**
	 * If the OMF file contains a "translator" record, this is usually a string
	 * indicating the compiler which produced the file.
	 * @return the translator for this file
	 */
	public String getTranslator() {
		return translator;
	}

	/**
	 * @return true if the file describes the load image for a little endian architecture
	 */
	public boolean isLittleEndian() {
		return isLittleEndian;
	}

	/**
	 * @return the list of segments in this file
	 */
	public ArrayList<OmfSegmentHeader> getSegments() {
		return segments;
	}

	/**
	 * @return the list of segments which are Borland extensions
	 */
	public ArrayList<OmfSegmentHeader> getExtraSegments() {
		return extraSeg;
	}

	/**
	 * @return the list of group records for this file
	 */
	public ArrayList<OmfGroupRecord> getGroups() {
		return groups;
	}

	/**
	 * @return the list of symbols that are external to this file
	 */
	public ArrayList<OmfExternalSymbol> getExternalSymbols() {
		return externsymbols;
	}

	/**
	 * @return the list of symbols exported by this file
	 */
	public ArrayList<OmfSymbolRecord> getPublicSymbols() {
		return symbols;
	}

	/**
	 * @return the list of relocation records for this file
	 */
	public ArrayList<OmfFixupRecord> getFixups() {
		return fixup;
	}

	/**
	 * Sort the explicit data-blocks for each segment into address order.
	 */
	public void sortSegmentDataBlocks() {
		if (extraSeg != null) {
			for (int i = 0; i < extraSeg.size(); ++i) {
				segments.add(extraSeg.get(i));
			}
		}
		for (int i = 0; i < segments.size(); ++i) {
			segments.get(i).sortData();
		}
	}

	/**
	 * Add a freshly parsed LEDATA record to its correct segment
	 * @param datablock is the LEDATA record
	 * @throws OmfException for a malformed segment index
	 */
	private void addEnumeratedBlock(OmfEnumeratedData datablock) throws OmfException {
		int index = datablock.getSegmentIndex();
		int subindex = -1;
		OmfSegmentHeader segment;
		if ((index & 0x4000) != 0) {
			subindex = index & 0x3fff;
			index = 1;
			segment = createOrFindBorlandSegment(subindex, 1);
		}
		else {
			if ((index <= 0) || (index > segments.size())) {
				throw new OmfException("Bad segment index");
			}
			segment = segments.get(index - 1);
		}
		if (subindex != -1) {
			segment.appendEnumeratedData(datablock);
		}
		else {
			segment.addEnumeratedData(datablock);
		}
	}

	/**
	 * Given an index, retrieve the specific segment it refers to. This
	 * incorporates the special Borland segments, where the index has 
	 * the bit 0x4000 set.
	 * @param index identifies the segment
	 * @return the corresponding OmfSegmentHeader
	 * @throws OmfException if the index is malformed
	 */
	public OmfSegmentHeader resolveSegment(int index) throws OmfException {
		int subindex = -1;
		OmfSegmentHeader res;
		if ((index & 0x4000) != 0) {
			subindex = index & 0x3fff;
			if ((subindex <= 0) || (subindex > extraSeg.size())) {
				throw new OmfException("Bad extra segment index");
			}
			res = extraSeg.get(subindex - 1);
			return res;
		}
		if ((index <= 0) || (index > segments.size())) {
			throw new OmfException("Bad segment index");
		}
		res = segments.get(index - 1);
		return res;
	}

	/**
	 * Resolve special names associated with each segment: segment, class, overlay names
	 * and group: group name
	 * For each segment, the read/write/execute permissions are also determined
	 * @throws OmfException if any name indices are malformed
	 */
	public void resolveNames() throws OmfException {
		for (int i = 0; i < segments.size(); ++i) {
			segments.get(i).resolveNames(nameList);
		}
		// extraSeg segments already have names
		for (int i = 0; i < groups.size(); ++i) {
			groups.get(i).resolveNames(nameList);
		}
	}

	/**
	 * Given an index, either find an existing Borland segment, or create a new one.
	 * Borland compilers can introduce special segments with a separate indexing
	 * scheme. These need to be stored in a separate list, while the loader needs
	 * to look up segments by index.
	 * @param index is the segment index
	 * @param datatype is the type of (new) segment
	 * @return the corresponding OmfSegmentHeader
	 */
	private OmfSegmentHeader createOrFindBorlandSegment(int index, int datatype) {
		if (extraSeg == null) {
			extraSeg = new ArrayList<OmfSegmentHeader>();
		}
		while (extraSeg.size() < index) {
			extraSeg.add(null);
		}
		OmfSegmentHeader segment = extraSeg.get(index - 1);
		if (segment == null) {
			segment = new OmfSegmentHeader(index, datatype);
			extraSeg.set(index - 1, segment);
		}
		return segment;
	}

	private void evaluateComdef(OmfComdefRecord comdef) {
		for (OmfSymbol sym : comdef.getSymbols()) {
			int dt = sym.getDataType();
			if (dt > 0 && dt < 0x60) {		// A special borland segment symbol
				int count = (extraSeg == null) ? 1 : extraSeg.size() + 1;
				createOrFindBorlandSegment(count, dt);
				sym.setSegmentRef(count);

			}
		}
	}

	/**
	 * Scan the object file, for the main header and comment records. Other records are parsed but not saved
	 * @param reader is the byte stream
	 * @param monitor is checked for cancellation
	 * @param fastscan is true if we only want to scan the header until first seghead,
	 * @return the header record
	 * @throws IOException for problems reading program data
	 * @throws OmfException for malformed records
	 */
	public static OmfFileHeader scan(BinaryReader reader, TaskMonitor monitor, boolean fastscan)
			throws IOException, OmfException {
		OmfRecord record = OmfRecord.readRecord(reader);
		if (!(record instanceof OmfFileHeader)) {
			throw new OmfException("Object file does not start with proper header");
		}
		OmfFileHeader header = (OmfFileHeader) record;

		while (true) {
			record = OmfRecord.readRecord(reader);

			if (monitor.isCancelled()) {
				break;
			}
			if (record instanceof OmfModuleEnd) {
				break;
			}

			if (record instanceof OmfCommentRecord comment) {
				switch (comment.getCommentClass()) {
					case OmfCommentRecord.COMMENT_CLASS_TRANSLATOR:
						header.translator = comment.getValue();
						break;
					case OmfCommentRecord.COMMENT_CLASS_LIBMOD:
						header.libModuleName = comment.getValue();
						break;
					case OmfCommentRecord.COMMENT_CLASS_WATCOM_SETTINGS:
						header.translator = "Watcom";
						break;
					case OmfCommentRecord.COMMENT_CLASS_MICROSOFT_SETTINGS:
						header.translator = "Microsoft";
						break;
				}
			}
			else if (record instanceof OmfSegmentHeader head) {
				header.format16bit = head.is16Bit();
				if (fastscan) {
					break;
				}
			}
		}
		return header;
	}

	/**
	 * Parse the entire object file
	 * 
	 * @param reader is the byte stream
	 * @param monitor is checked for cancel button
	 * @param log the log
	 * @return the header record as root of object
	 * @throws IOException for problems reading data
	 * @throws OmfException for malformed records
	 */
	public static OmfFileHeader parse(BinaryReader reader, TaskMonitor monitor, MessageLog log)
			throws IOException, OmfException {
		OmfRecord record = OmfRecord.readRecord(reader);
		if (!(record instanceof OmfFileHeader)) {
			throw new OmfException("Object file does not start with proper header");
		}
		OmfFileHeader header = (OmfFileHeader) record;
		OmfData lastDataBlock = null;

		while (true) {
			record = OmfRecord.readRecord(reader);

			if (monitor.isCancelled()) {
				break;
			}
			if (record instanceof OmfModuleEnd) {
				break;
			}

			if (record instanceof OmfCommentRecord comment) {
				byte commentClass = comment.getCommentClass();
				if (commentClass == OmfCommentRecord.COMMENT_CLASS_TRANSLATOR) {
					header.translator = comment.getValue();
				}
				else if (commentClass == OmfCommentRecord.COMMENT_CLASS_LIBMOD) {
					header.libModuleName = comment.getValue();
				}
			}
			else if (record instanceof OmfComdefRecord comdef) {
				header.evaluateComdef(comdef);
				header.externsymbols.add((OmfExternalSymbol) record);
			}
			else if (record instanceof OmfComdatExternalSymbol comdat) {
				comdat.loadNames(header.nameList);
				header.externsymbols.add(comdat);
			}
			else if (record instanceof OmfExternalSymbol external) {
				header.externsymbols.add(external);
			}
			else if (record instanceof OmfSymbolRecord symbol) {
				header.symbols.add(symbol);
			}
			else if (record instanceof OmfNamesRecord names) {
				names.appendNames(header.nameList); // Keep names, otherwise don't save record
			}
			else if (record instanceof OmfSegmentHeader seghead) {
				header.segments.add(seghead);
			}
			else if (record instanceof OmfGroupRecord group) {
				header.groups.add(group);
			}
			else if (record instanceof OmfFixupRecord fixuprec) {
				fixuprec.setDataBlock(lastDataBlock);
				header.fixup.add(fixuprec);
			}
			else if (record instanceof OmfEnumeratedData enumheader) {
				header.addEnumeratedBlock(enumheader);
				lastDataBlock = enumheader;
			}
			else if (record instanceof OmfIteratedData iterheader) {
				if (iterheader.getSegmentIndex() <= 0 ||
					iterheader.getSegmentIndex() > header.segments.size()) {
					throw new OmfException("Bad segment index on LIDATA");
				}
				OmfSegmentHeader segheader2 = header.segments.get(iterheader.getSegmentIndex() - 1);
				segheader2.addIteratedData(iterheader);
				lastDataBlock = iterheader;
			}
			else if (record instanceof OmfUnsupportedRecord) {
				// TODO: Should we always set lastDataBlock to null?
				if (record.getRecordType() == COMDAT) {
					lastDataBlock = null;
				}
				logRecord("Unsupported OMF record", record, log);
			}
			else if (record instanceof OmfObsoleteRecord) {
				logRecord("Obsolete OMF record", record, log);
			}
			else if (record instanceof OmfUnknownRecord) {
				logRecord("Unknown OMF record", record, log);
			}
		}
		return header;
	}

	/**
	 * Assign a load image address to each segment. Follow OMF rules for grouping and ordering
	 * the segments in memory.
	 * @param startAddress is the base memory address for the load image
	 * @param segments is the list of segments
	 * @param groups is the list of specific segments that are grouped together in memory
	 * @throws OmfException for malformed index/alignment/combining fields
	 */
	public static void doLinking(long startAddress, ArrayList<OmfSegmentHeader> segments,
			ArrayList<OmfGroupRecord> groups) throws OmfException {
		// Link anything in groups first
		for (int i = 0; i < groups.size(); ++i) {
			OmfGroupRecord group = groups.get(i);
			group.setStartAddress(startAddress);
			for (int j = 0; j < group.numSegments(); ++j) {
				int index = group.getSegmentIndex(j);
				try {
					OmfSegmentHeader segment = segments.get(index - 1);
					startAddress = segment.relocateSegment(startAddress, -1);
				}
				catch (IndexOutOfBoundsException ex) {
					throw new OmfException(ex.getMessage());
				}
			}
		}

		// Fill in any remaining segments
		for (int i = 0; i < segments.size(); ++i) {
			OmfSegmentHeader segment = segments.get(i);
			if (segment.getStartAddress() != -1) {
				continue;		// Address already assigned
			}

			startAddress = segment.relocateSegment(startAddress, -1);
			// Look for any segments with same name,class which should be officially "combined" with this segment
			for (int j = i + 1; j < segments.size(); ++j) {
				OmfSegmentHeader combineSeg = segments.get(j);
				if (combineSeg.getStartAddress() != -1) {
					continue;
				}
				if (!combineSeg.getName().equals(segment.getName())) {
					continue;
				}
				if (!combineSeg.getClassName().equals(segment.getClassName())) {
					continue;
				}
				int C = combineSeg.getCombine();
				if (C == 0) {
					continue;			// Private segment
				}
				if (C == 2 || C == 4 || C == 7) {
					startAddress = combineSeg.relocateSegment(startAddress, -1);
				}
				else if (C == 5) {
					startAddress = combineSeg.relocateSegment(startAddress, 1);
				}
				else {
					throw new OmfException("Combine type not supported");
				}
			}
		}
	}

	/**
	 * Check that the file has the specific OMF magic number
	 * @param reader accesses the bytes of the file
	 * @return true if the magic number matches
	 * @throws IOException for problems reading bytes
	 */
	public static boolean checkMagicNumber(BinaryReader reader) throws IOException {
		byte first = reader.readNextByte();
		if ((first & 0xfc) != 0x80) {
			return false;
		}
		int len = reader.readNextShort() & 0xffff;
		int stringlen = reader.readNextByte() & 0xff;
		if (len != stringlen + 2) {
			return false;
		}
		return true;
	}

	/**
	 * Create a reader for a specific OMF file
	 * @param provider is the underlying ByteProvider
	 * @return the new reader
	 */
	public static BinaryReader createReader(ByteProvider provider) {
		return new BinaryReader(provider, true/* Always little endian */);
	}

	private static void logRecord(String description, OmfRecord record, MessageLog log) {
		log.appendMsg(description + " (" + record + ")");
	}
}
