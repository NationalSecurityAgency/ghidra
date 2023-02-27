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
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import ghidra.app.util.bin.BinaryReader;

public abstract class OmfRecord {
	public final static byte RHEADR = (byte) 0x6E; // Obsolete
	public final static byte REGINT = (byte) 0x70; // Obsolete
	public final static byte REDATA = (byte) 0x72; // Obsolete
	public final static byte RIDATA = (byte) 0x74; // Obsolete
	public final static byte OVLDEF = (byte) 0x76; // Obsolete 
	public final static byte ENDREC = (byte) 0x78; // Obsolete 
	public final static byte BLKDEF = (byte) 0x7A; // Obsolete
	public final static byte BLKEND = (byte) 0x7C; // Obsolete
	public final static byte DEBSYM = (byte) 0x7E; // Obsolete
	public final static byte THEADR = (byte) 0x80;
	public final static byte LHEADR = (byte) 0x82;
	public final static byte PEDATA = (byte) 0x84; // Obsolete
	public final static byte PIDATA = (byte) 0x86; // Obsolete
	public final static byte COMENT = (byte) 0x88;
	public final static byte MODEND = (byte) 0x8A;
	public final static byte EXTDEF = (byte) 0x8C;
	public final static byte TYPDEF = (byte) 0x8E; // Obsolete 
	public final static byte PUBDEF = (byte) 0x90;
	public final static byte LOCSYM = (byte) 0x92; // Obsolete
	public final static byte LINNUM = (byte) 0x94;
	public final static byte LNAMES = (byte) 0x96;
	public final static byte SEGDEF = (byte) 0x98;
	public final static byte GRPDEF = (byte) 0x9A;
	public final static byte FIXUPP = (byte) 0x9C;
	public final static byte LEDATA = (byte) 0xA0;
	public final static byte LIDATA = (byte) 0xA2;
	public final static byte LIBHED = (byte) 0xA4; // Obsolete
	public final static byte LIBNAM = (byte) 0xA6; // Obsolete
	public final static byte LIBLOC = (byte) 0xA8; // Obsolete
	public final static byte LIBDIC = (byte) 0xAA; // Obsolete
	public final static byte COMDEF = (byte) 0xB0;
	public final static byte BAKPAT = (byte) 0xB2;
	public final static byte LEXTDEF = (byte) 0xB4;
	public final static byte LPUBDEF = (byte) 0xB6;
	public final static byte LCOMDEF = (byte) 0xB8;
	public final static byte CEXTDEF = (byte) 0xBC;
	public final static byte COMDAT = (byte) 0xC2;
	public final static byte LINSYM = (byte) 0xC4;
	public final static byte ALIAS = (byte) 0xC6;
	public final static byte NBKPAT = (byte) 0xC8;
	public final static byte LLNAMES = (byte) 0xCA;
	public final static byte VERNUM = (byte) 0xCC;
	public final static byte VENDEXT = (byte) 0xCE;
	public final static byte START = (byte) 0xF0;
	public final static byte END = (byte) 0xF1;

	protected byte recordType;
	protected int recordLength;
	protected long recordOffset;
	protected byte checkSum;

	public byte getRecordType() {
		return recordType;
	}

	public int getRecordLength() {
		return recordLength;
	}

	public long getRecordOffset() {
		return recordOffset;
	}

	public void readRecordHeader(BinaryReader reader) throws IOException {
		recordOffset = reader.getPointerIndex();
		recordType = reader.readNextByte();
		recordLength = reader.readNextShort() & 0xffff;
	}

	public void readCheckSumByte(BinaryReader reader) throws IOException {
		checkSum = reader.readNextByte();
	}

	public byte calcCheckSum(BinaryReader reader) throws IOException {
		byte res = reader.readNextByte();
		res += reader.readNextByte();
		res += reader.readNextByte();		// Sum the record header bytes
		for (int i = 0; i < recordLength; ++i)
			res += reader.readNextByte();
		return res;
	}

	public boolean validCheckSum(BinaryReader reader) throws IOException {
		if (checkSum == 0)
			return true;			// Sum compilers just set this to zero
		return (calcCheckSum(reader) == 0);
	}

	public boolean hasBigFields() {
		return ((recordType & 1) != 0);
	}

	public static int readInt1Or2(BinaryReader reader, boolean isBig) throws IOException {
		if (isBig)
			return (reader.readNextShort() & 0xffff);
		return (reader.readNextByte() & 0xff);
	}

	public static int readInt2Or4(BinaryReader reader, boolean isBig) throws IOException {
		if (isBig)
			return reader.readNextInt();
		return (reader.readNextShort() & 0xffff);
	}

	public static int readIndex(BinaryReader reader) throws IOException {
		int indexWord;
		byte firstByte = reader.readNextByte();
		if ((firstByte & 0x80) != 0) {
			indexWord = (firstByte & 0x7f) * 0x100 + (reader.readNextByte() & 0xff);
		}
		else {
			indexWord = firstByte;
		}
		return indexWord;
	}

	public static OmfRecord readRecord(BinaryReader reader) throws IOException, OmfException {
		byte type = reader.peekNextByte();
		type &= 0xfe;	// Mask off the least significant bit (16/32 bit flag)
		return switch (type) {
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
				yield new OmfUnsupportedRecord(reader);
			default:
				yield new OmfUnknownRecord(reader);
		};
	}

	/**
	 * Read the OMF string format: 1-byte length, followed by that many ascii characters
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the string
	 * @return the read OMF string
	 * @throws IOException if an IO-related error occurred
	 */
	public static String readString(BinaryReader reader) throws IOException {
		int count = reader.readNextByte() & 0xff;
		return reader.readNextAsciiString(count);
	}

	/**
	 * Gets the name of the given record type
	 * 
	 * @param type The record type
	 * @return The name of the given record type
	 */
	public final static String getRecordName(int type) {
		for (Field field : OmfRecord.class.getDeclaredFields()) {
			int modifiers = field.getModifiers();
			if (Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
				try {
					Byte value = (Byte) field.get(null);
					if (type == value) {
						return field.getName();
					}
				}
				catch (Exception e) {
					break;
				}
			}
		}
		return "<UNKNOWN>";
	}

	@Override
	public String toString() {
		return String.format("name: %s, type: 0x%x, offset: 0x%x, length: 0x%x",
			getRecordName(recordType & (byte) 0xfe), recordType, recordOffset, recordLength);
	}
}
