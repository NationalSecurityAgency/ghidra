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
package ghidra.pdb.pdbreader;

import java.io.IOException;
import java.io.Writer;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Global Symbol Information component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class GlobalSymbolInformation {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;
	protected int lengthHashRecordsBitMap;
	protected int numHashRecords;

	private long headerSignature;
	private long versionNumber;
	private int lengthHashRecords;
	private int lengthBuckets;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdbIn {@link AbstractPdb} that owns the Global Symbol Information to process.
	 */
	public GlobalSymbolInformation(AbstractPdb pdbIn) {
		pdb = pdbIn;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserialize the {@link GlobalSymbolInformation} from the appropriate stream in the Pdb.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	@SuppressWarnings("unused") // for buf1Reader and buf2Reader--still under investigation.
	void deserialize(TaskMonitor monitor) throws IOException, PdbException, CancelledException {
		if (pdb.minimalDebugInfo) {
			//Maybe 0x200 for some and 0x201 for others? 0x200 works for cn3.pdb
			lengthHashRecordsBitMap = 0x200;
			numHashRecords = 0x1000;
		}
		else {
			lengthHashRecordsBitMap = 0x8000;
			numHashRecords = 0x3ffff; //0x40000?
		}
		int streamNumber = pdb.databaseInterface.getGlobalSymbolsHashMaybeStreamNumber();
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
		//System.out.println(reader.dump());

		deserializeHeader(reader);

		PdbByteReader buf1Reader = reader.getSubPdbByteReader(lengthHashRecords);
		//System.out.println(buf1Reader.dump());
		PdbByteReader buf2Reader = reader.getSubPdbByteReader(lengthBuckets);
//	junkCheck(buf1, buf2); // TODO: this contains experiments if we want to do more.
		//System.out.println(buf2Reader.dump());
		if (reader.hasMore()) {
			assert false;
		}

		//parser.deserializeSymbolRecords(reader);
		//TODO: left off here 20180717

	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	// TODO: this contains some experiments for investigating hash reconstruction.  Not sure
	//  that we need the GlobalSymbolInformation hash table.  The GlobalSymbolInformation is
	//  supposed to be a "search" mechanism for searching based symbol names.
	// The PublicSymbolInformation is for searching (hash) based upon addresses.  Don't need
	//  it either, I think.
	@SuppressWarnings("unused")
	private void junkCheck(byte[] bytes1, byte[] bytes2) throws PdbException {
		System.out.println("length1: " + bytes1.length);
		System.out.println("length2: " + bytes2.length);

		//Count bits.
		int count = 0;
		byte x;
		for (int i = 0; i < 0x200; i++) {
			x = bytes2[i];
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
			x >>= 1;
			count += (x & 0x01);
		}
		System.out.println("Bit count: " + count);

		// Bits are used to expand the rest of bytes2.  I can see from cn3.cpp, that
		// there are 1530 bits set and this is exactly how many records remain beyond
		// 0x200 offset.  See gsi.cpp: ExpandBuckets as called by readHash(), which is the
		// high level mechanism for reconstructing the hash table.

		//Check values.
		PdbByteReader reader = new PdbByteReader(bytes2);
		reader.parseBytes(0x200);
		int minx1 = Integer.MAX_VALUE;
		int maxx1 = Integer.MIN_VALUE;
		while (reader.hasMore()) {
			int x1 = reader.parseInt();
			minx1 = Math.min(minx1, x1);
			maxx1 = Math.max(maxx1, x1);
		}
		if (maxx1 > bytes1.length) {
			// Adjust (/12 then *8) offsets seen like x1 in loop above.  These are then offsets
			//  into the bytes1. Then a mechanisms like fixHashiIn() from gsi.cpp would need to
			//  be done to create full hash table.  Also the "hash" routine (see gsi and misc.h)
			//  would need to be implemented to hash the "item" (as I'll call it) coming in...
			//  see methods like gsi.cpp: getEnumSyms(), which utilizes the hash table and hash
			//  alg.  IMPORTANT: I do not know if we "have to have this."  Can we get all we
			//  need without this hash mechanism?
		}
		System.out.println("minx1: " + minx1);
		System.out.println("maxx1: " + maxx1);
	}

	/**
	 * Deserialize the header of the {@link GlobalSymbolInformation} from the appropriate stream
	 *  in the PDB.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	void deserializeHeader(PdbByteReader reader) throws PdbException {
		headerSignature = reader.parseUnsignedIntVal();
		versionNumber = reader.parseUnsignedIntVal();
		lengthHashRecords = reader.parseInt();
		lengthBuckets = reader.parseInt();
	}

	/**
	 * Debug method for dumping information from this {@link GlobalSymbolInformation}.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dump(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("GlobalSymbolInformation-------------------------------------\n");
		dumpHeader(builder);
		//builder.append(": " + );
		builder.append("\nEnd GlobalSymbolInformation---------------------------------\n");
		writer.write(builder.toString());
	}

	/**
	 * Debug method for dumping information from this {@link GlobalSymbolInformation} header.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	protected void dumpHeader(StringBuilder builder) {
//		System.out.println(String.format("GSI: %08x %08x %d %d", headerSignature, versionNumber,
//		lengthHashRecords, lengthBuckets));
		builder.append("GlobalSymbolInformationHeader-------------------------------\n");
		builder.append("headerSignature: ");
		builder.append(headerSignature);
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nlengthHashRecords: ");
		builder.append(lengthHashRecords);
		builder.append("\nlengthBuckets: ");
		builder.append(lengthBuckets);
		builder.append("\n End GlobalSymbolInformationHeader--------------------------\n");
	}
}
