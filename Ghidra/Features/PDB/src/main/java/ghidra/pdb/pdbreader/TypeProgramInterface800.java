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

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is the version of {@link AbstractTypeProgramInterface} for Microsoft v8.00 PDB.
 */
public class TypeProgramInterface800 extends AbstractTypeProgramInterface {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected int headerLength;
	protected TypeProgramInterfaceHash hash;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this {@link AbstractTypeProgramInterface}.
	 * @param streamNumber The stream number that contains the {@link AbstractTypeProgramInterface}.
	 */
	public TypeProgramInterface800(AbstractPdb pdb, int streamNumber) {
		super(pdb, streamNumber);
		hash = new TypeProgramInterfaceHash();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void deserializeHeader(PdbByteReader reader) throws PdbException {
		versionNumber = reader.parseInt();
		headerLength = reader.parseInt();
		typeIndexMin = reader.parseInt();
		typeIndexMaxExclusive = reader.parseInt();
		dataLength = reader.parseInt();
		hash.deserialize(reader);
		// Commented out, but this is currently where we would put this method.  See the note
		//  place within the method (deserializeHashStreams()) for more information about why
		//  we have this commented out.
//		try {
//			hash.deserializeHashStreams(pdb);
//		}
//		catch (PdbException e) {
//			//TODO: handle exception.
//		}
	}

	@Override
	protected String dumpHeader() {
		StringBuilder builder = new StringBuilder();
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nheaderLength: ");
		builder.append(headerLength);
		builder.append("\ntypeIndexMin: ");
		builder.append(typeIndexMin);
		builder.append("\ntypeIndexMaxExclusive: ");
		builder.append(typeIndexMaxExclusive);
		builder.append("\ndataLength: ");
		builder.append(dataLength);
		builder.append("\n");
		builder.append(hash.dump());
		return builder.toString();
	}

	//==============================================================================================
	// Private Classes
	//==============================================================================================
	protected class TypeProgramInterfaceHash {
		int streamNumber;
		int streamNumberAuxilliary;
		int hashKeySize;
		int numHashBins;
		int offsetHashVals;
		int lengthHashVals;
		int offsetTypeInfoOffsetPairs;
		int lengthTypeInfoOffsetPairs;
		int offsetHashAdjustment;
		int lengthHashAdjustment;

		/**
		 * Deserializes the {@link TypeProgramInterfaceHash}.
		 * @param reader {@link PdbByteReader} from which to deserialize the data.
		 * @throws PdbException Upon not enough data left to parse.
		 */
		protected void deserialize(PdbByteReader reader) throws PdbException {
			streamNumber = reader.parseUnsignedShortVal();
			streamNumberAuxilliary = reader.parseUnsignedShortVal();
			hashKeySize = reader.parseInt();
			numHashBins = reader.parseInt();
			offsetHashVals = reader.parseInt();
			lengthHashVals = reader.parseInt();
			offsetTypeInfoOffsetPairs = reader.parseInt();
			lengthTypeInfoOffsetPairs = reader.parseInt();
			offsetHashAdjustment = reader.parseInt();
			lengthHashAdjustment = reader.parseInt();
		}

		// TODO: parsing not complete
		// Suppress "unused" for hashBuffer, typeInfoOffsetPairsBuffer, hashAdjustmentBuffer
		/**
		 * *UNDER CONSTRUCTION* Deserializes the Hash Streams...
		 * @param monitor {@link TaskMonitor} used for checking cancellation.
		 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
		 *  inability to read required bytes.
		 * @throws PdbException Upon error in processing components.
		 * @throws CancelledException Upon user cancellation.
		 */
		@SuppressWarnings("unused")
		protected void deserializeHashStreams(TaskMonitor monitor)
				throws IOException, PdbException, CancelledException {
			// I don't believe we need to parse and process the hash table.  They seemingly are
			//  used to point from a TypeIndex to a raw (byte[]) Type Record.  We are not
			//  currently maintaining our records in this raw form; we are processing (parsing) 
			//  them as we read each record buffer.
			// So... we are not going to do anything more with this method.  Note: with real
			//  data, we could see that each of the subsections notated by offset/length
			//  fell nicely into the complete stream.  I am commenting this code out below.
			// Also note that we have no evidence of how the Auxilliary stream is used.  Its
			//  contents might need to get concatenated with the contents of the primary
			//  stream before the processing takes place, but the API does not show it being
			//  used at all.
			if (streamNumber == 0xffff) {
				return;
			}
			PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
			//System.out.println(reader.dump());
			reader.setIndex(offsetHashVals);
			byte[] hashBuffer = reader.parseBytes(lengthHashVals);
			reader.setIndex(offsetTypeInfoOffsetPairs);
			byte[] typeInfoOffsetPairsBuffer = reader.parseBytes(lengthTypeInfoOffsetPairs);
			reader.setIndex(offsetHashAdjustment);
			byte[] hashAdjustmentBuffer = reader.parseBytes(lengthHashAdjustment);
			if (streamNumberAuxilliary == 0xffff) {
				return;
			}
			PdbByteReader readerAuxilliary =
				pdb.getReaderForStreamNumber(streamNumberAuxilliary, monitor);
			//readerAuxilliary.dump();
		}

		/**
		 * Dumps the this {@link TypeProgramInterfaceHash}.  This method is for debugging only.
		 * @return {@link String} of pretty output.
		 */
		protected String dump() {
			StringBuilder builder = new StringBuilder();
			builder.append("Hash--------------------------------------------------------");
			builder.append("\nstreamNumber: ");
			builder.append(streamNumber);
			builder.append("\nstreamNumberAuxilliary: ");
			builder.append(streamNumberAuxilliary);
			builder.append("\nhashKeySize: ");
			builder.append(hashKeySize);
			builder.append("\nnumHashBins: ");
			builder.append(numHashBins);
			builder.append("\noffsetHashVals: ");
			builder.append(offsetHashVals);
			builder.append("\nlengthHashVals: ");
			builder.append(lengthHashVals);
			builder.append("\noffsetTypeInfoOffsetPairs: ");
			builder.append(offsetTypeInfoOffsetPairs);
			builder.append("\nlengthTypeInfoOffsetPairs: ");
			builder.append(lengthTypeInfoOffsetPairs);
			builder.append("\noffsetHashAdjustment: ");
			builder.append(offsetHashAdjustment);
			builder.append("\nlengthHashAdjustment: ");
			builder.append(lengthHashAdjustment);
			return builder.toString();
		}
	}

}
