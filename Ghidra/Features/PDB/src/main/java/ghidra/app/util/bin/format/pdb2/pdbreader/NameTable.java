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
import java.util.*;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Name Table component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class NameTable {

	private static final long HEADER_MAGIC = 0xeffeeffeL;

	//==============================================================================================
	// Internals
	//==============================================================================================
	private AbstractPdb pdb;

	private int nameBufferSize = 0;
	private int numPairs = 0;
	private int domainSize = 0;
	private DenseIntegerArray presentList = new DenseIntegerArray();
	private DenseIntegerArray deletedList = new DenseIntegerArray();
	private String[] names;
	private int[] streamNumbers;
	private Map<String, Integer> streamNumbersByName = new HashMap<>();
	private Map<Integer, String> namesByStreamNumber = new HashMap<>();
	private Map<Integer, Map<Integer, String>> stringTablesByStreamNumber = new HashMap<>();

	private Map<Integer, String> namesByOffset;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this Name Table.
	 */
	public NameTable(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Returns a name from the Name Table pertaining to the index argument.
	 * @param index Index of the name to retrieve.
	 * @return Name retrieved for the index.
	 */
	public String getNameFromStreamNumber(int index) {
		return namesByStreamNumber.get(index);
	}

	/**
	 * Returns an index of the name argument in the {@link NameTable}.
	 * @param name Name to look up.
	 * @return Index of the name.
	 */
	public int getStreamNumberFromName(String name) {
		Integer x = streamNumbersByName.getOrDefault(name, -1);
		return x;
	}

	/**
	 * Returns a name from the Name Table pertaining to the byte-offset in the block of names for
	 *  the table.
	 * @param offset Byte-offset of the name in the {@link NameTable} block.
	 * @return Name found at offset.
	 */
	public String getNameStringFromOffset(int offset) {
		if (namesByOffset == null) {
			return null;
		}
		return namesByOffset.get(offset);
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.  Add a paired offset and {@link String} name.
	 * @param offset Offset part of pair.
	 * @param name Name part of pair.
	 */
	public void forTestingOnlyAddOffsetNamePair(int offset, String name) {
		if (namesByOffset == null) {
			namesByOffset = new HashMap<>();
		}
		namesByOffset.put(offset, name);

	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	// TODO: Regarding String conversions... We expect that US_ASCII could be a problem, but it
	//  is probably better than creating the String without any code set chosen at all.  Do we
	//  need to change all processing of Strings within the PDB so that we are only creating byte 
	//  arrays with some notional idea (1 byte, 2 byte, possibly utf-8, utf-16, wchar_t, or
	//  "unknown" and defer true interpretation/conversion to String until we know or until
	//  Ghidra user can ad-hoc apply interpretations to those fields?  Needs investigation, but
	//  not critical at this time.
	/**
	 * Deserializes the Directory.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a string.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserializeDirectory(PdbByteReader reader, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {

		// Get the buffer of strings
		nameBufferSize = reader.parseInt();
		PdbByteReader nameBufferReader = reader.getSubPdbByteReader(nameBufferSize);

		// Get the number of pairs and the number of entries (which should be 2 * number of pairs)
		numPairs = reader.parseInt();
		domainSize = reader.parseInt();

		// Using an arbitrary-valued check here for a number too big.
		//  Really do not expect there to be many names in name table (from experience); could
		//  be on the order of 1 or 10.
		if (numPairs > 0x100000) {
			throw new PdbException("Num Pairs too large.");
		}
		if (numPairs < 0) {
			throw new PdbException("Illegal negative value.");
		}

		names = new String[numPairs];
		streamNumbers = new int[numPairs];

		// Read Present Set.  Not really needed by us, as we use the java HashMap.
		presentList.parse(reader, monitor);

		// Read Deleted Set.  Not really needed by us, as we use the java HashMap.
		deletedList.parse(reader, monitor);

		// Read values of index into buffer and name index.  Load the HashMaps.
		// Since we are using the java HashMap, we do not need to mimic the
		// isPresent Dense Bit Array List (which would, instead, use a for-loop limit
		// of domainSize) and do not need to store the domain and range items
		// in a list indexed by i.
		for (int i = 0; i < numPairs; i++) {
			monitor.checkCanceled();
			int bufOffset = reader.parseInt();
			int streamNumber = reader.parseInt();
			nameBufferReader.setIndex(bufOffset);
			String name = nameBufferReader.parseNullTerminatedString(
				pdb.getPdbReaderOptions().getOneByteCharset());
			streamNumbers[i] = streamNumber;
			names[i] = name;
			namesByStreamNumber.put(streamNumber, name);
			streamNumbersByName.put(name, streamNumber);
		}
		deserializeNameTableStreams(monitor);
	}

	// TODO: Reduce code complexity once we know the details for the various cases.  Probably
	//  should create an abstract map class with derived types for each format we eventually
	//  find here.
	/**
	 * Deserializes Name Table Streams.  An offset-to-string map is created for each stream; each
	 *  map is placed into a stream-number-to-map map.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a string.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserializeNameTableStreams(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		for (int streamNumber : streamNumbers) {
			monitor.checkCanceled();
			Map<Integer, String> stringsByOffset = new HashMap<>();
			PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
			if (reader.getLimit() >= 12) {
				long hdrMagic = reader.parseUnsignedIntVal();
				int hdrVer = reader.parseInt();
				if ((hdrMagic == HEADER_MAGIC) && (hdrVer != 0)) {
					switch (hdrVer) {
						case 1:
							// We know this works ver hdrVer==1.
							int length = reader.parseInt();
							PdbByteReader stringReader = reader.getSubPdbByteReader(length);
							while (stringReader.hasMore()) {
								monitor.checkCanceled();
								int offset = stringReader.getIndex();
								String string = stringReader.parseNullTerminatedUtf8String();
								stringsByOffset.put(offset, string);
							}
							// TODO: ? process the rest of the data in reader ?
							break;
						case 2:
						default:
							// TODO: unknown format
							break;
					}
				}
				else {
					// Back up for nonexistent hdrMagic and hdrVer.
					reader.setIndex(reader.getIndex() - 8);
					// TODO: unknown format
				}
			}
			stringTablesByStreamNumber.put(streamNumber, stringsByOffset);
		}

		int namesStreamNumber = getStreamNumberFromName("/names");
		namesByOffset = stringTablesByStreamNumber.get(namesStreamNumber);

	}

	/**
	 * Dumps the Name Table.  This method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("NameTable---------------------------------------------------");
		builder.append("\nnameBufferSize: ");
		builder.append(nameBufferSize);
		builder.append("\nnumPairs: ");
		builder.append(numPairs);
		builder.append("\ndomainSize: ");
		builder.append(domainSize);
		builder.append("\nmaxPossiblePresent: ");
		builder.append(presentList.getMaxPossible());
		builder.append("\nPresent: {");
		boolean firstSeen = false;
		for (int i = 0; i < presentList.getMaxPossible(); i++) {
			if (presentList.contains(i)) {
				if (firstSeen) {
					builder.append(", ");
				}
				else {
					firstSeen = true;
				}
				builder.append(i);
			}
		}
		builder.append("}");
		builder.append("\nmaxPossibleDeleted: ");
		builder.append(deletedList.getMaxPossible());
		builder.append("\nDeleted: {");
		firstSeen = false;
		for (int i = 0; i < deletedList.getMaxPossible(); i++) {
			if (deletedList.contains(i)) {
				if (firstSeen) {
					builder.append(", ");
				}
				else {
					firstSeen = true;
				}
				builder.append(i);
			}
		}
		builder.append("}\n");
		builder.append("------------------------------------------------------------\n");
		for (String name : streamNumbersByName.keySet()) {
			builder.append(name);
			builder.append(" : ");
			builder.append(streamNumbersByName.get(name));
			builder.append("\n");
		}
		builder.append("------------------------------------------------------------\n");
		for (int streamNumber : namesByStreamNumber.keySet()) {
			builder.append(streamNumber);
			builder.append(" : ");
			builder.append(namesByStreamNumber.get(streamNumber));
			builder.append("\n");
		}
		// TODO: output map entries for each table.
		builder.append("End NameTable-----------------------------------------------\n");
		return builder.toString();
	}

}
