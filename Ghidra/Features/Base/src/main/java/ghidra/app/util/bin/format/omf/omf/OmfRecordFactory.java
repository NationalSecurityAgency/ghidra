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
package ghidra.app.util.bin.format.omf.omf;

import static ghidra.app.util.bin.format.omf.omf.OmfRecordTypes.*;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.omf.*;

/**
 * A class for reading/creating Relocatable OMF records
 */
public class OmfRecordFactory extends AbstractOmfRecordFactory {

	/**
	 * Creates a new {@link OmfRecordFactory}
	 * 
	 * @param provider The {@link ByteProvider} that contains the records
	 */
	public OmfRecordFactory(ByteProvider provider) {
		super(new BinaryReader(provider, true));
	}

	@Override
	public OmfRecord readNextRecord() throws IOException, OmfException {
		int type = Byte.toUnsignedInt(reader.peekNextByte());
		OmfRecord record = switch (type & 0xfffffffe) { // mask off the least significant bit (16/32 bit flag)
			case THEADR:
			case LHEADR:
				yield new OmfFileHeader(reader);
			case COMENT:
				yield new OmfCommentRecord(reader);
			case MODEND:
				yield new OmfModuleEnd(reader);
			case EXTDEF:
				yield new OmfExternalSymbol(reader, false);
			case PUBDEF:
				yield new OmfSymbolRecord(reader, false);
			case LNAMES:
				yield new OmfNamesRecord(reader);
			case SEGDEF:
				yield new OmfSegmentHeader(reader);
			case GRPDEF:
				yield new OmfGroupRecord(reader);
			case FIXUPP:
				yield new OmfFixupRecord(reader);
			case LEDATA:
				yield new OmfEnumeratedData(reader);
			case LIDATA:
				yield new OmfIteratedData(reader);
			case COMDEF:
				yield new OmfComdefRecord(reader, false);
			case LEXTDEF:
				yield new OmfExternalSymbol(reader, true);
			case LPUBDEF:
				yield new OmfSymbolRecord(reader, true);
			case LCOMDEF:
				yield new OmfComdefRecord(reader, true);
			case CEXTDEF:
				yield new OmfComdatExternalSymbol(reader);
			case RHEADR:
			case REGINT:
			case REDATA:
			case RIDATA:
			case OVLDEF:
			case ENDREC:
			case BLKDEF:
			case BLKEND:
			case DEBSYM:
			case LINNUM:
			case PEDATA:
			case PIDATA:
			case LIBHED:
			case LIBNAM:
			case LIBLOC:
			case LIBDIC:
				yield new OmfObsoleteRecord(reader);
			case LOCSYM:
			case TYPDEF:
			case COMDAT:
			case LINSYM:
			case ALIAS:
			case BAKPAT:
			case NBKPAT:
			case LLNAMES:
			case VERNUM:
			case VENDEXT:
				yield new OmfUnsupportedRecord(reader, OmfRecordTypes.class);
			default:
				yield new OmfUnknownRecord(reader);
		};

		record.parseData();
		return record;
	}

	@Override
	public List<Integer> getStartRecordTypes() {
		return List.of(THEADR, LHEADR);
	}

	@Override
	public int getEndRecordType() {
		return MODEND;
	}
}
