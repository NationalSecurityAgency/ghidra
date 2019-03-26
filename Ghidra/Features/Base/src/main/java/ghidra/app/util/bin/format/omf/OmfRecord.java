/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.util.bin.BinaryReader;

public abstract class OmfRecord {
	public final static byte THEADR = (byte)0x80;
	public final static byte LHEADR = (byte)0x82;
	public final static byte COMENT = (byte)0x88;
	public final static byte MODEND = (byte)0x8A;
	public final static byte EXTDEF = (byte)0x8C;
	public final static byte PUBDEF = (byte)0x90;
	public final static byte LINNUM = (byte)0x94;
	public final static byte LNAMES = (byte)0x96;
	public final static byte SEGDEF = (byte)0x98;
	public final static byte GRPDEF = (byte)0x9A;
	public final static byte FIXUPP = (byte)0x9C;
	public final static byte LEDATA = (byte)0xA0;
	public final static byte LIDATA = (byte)0xA2;
	public final static byte COMDEF = (byte)0xB0;
	public final static byte LEXTDEF = (byte)0xB4;
	public final static byte LPUBDEF = (byte)0xB6;
	public final static byte LCOMDEF = (byte)0xB8;
	protected byte recordType;
	protected int recordLength;
	protected byte checkSum;

	public byte getRecordType() {
		return recordType;
	}
	
	public int getRecordLength() {
		return recordLength;
	}
	
	public void readRecordHeader(BinaryReader reader) throws IOException {
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
		for(int i=0;i<recordLength;++i)
			res += reader.readNextByte();
		return res;
	}
	
	public boolean validCheckSum(BinaryReader reader) throws IOException {
		if (checkSum == 0) return true;			// Sum compilers just set this to zero
		return (calcCheckSum(reader) == 0);
	}
	
	public boolean hasBigFields() {
		return ((recordType & 1)!=0);
	}
	
	public static int readInt1Or2(BinaryReader reader,boolean isBig) throws IOException {
		if (isBig)
			return (reader.readNextShort()  & 0xffff);
		return (reader.readNextByte() & 0xff);
	}
	
	public static int readInt2Or4(BinaryReader reader,boolean isBig) throws IOException {
		if (isBig)
			return reader.readNextInt();
		return (reader.readNextShort() & 0xffff);
	}
	
	public static int readIndex(BinaryReader reader) throws IOException {
		int indexWord;
		byte firstByte = reader.readNextByte();
		if ((firstByte & 0x80)!=0)
			indexWord = (firstByte & 0x7f) * 0x100 + (reader.readNextByte() & 0xff);
		else
			indexWord = firstByte;
		return indexWord;
	}
	
	public static OmfRecord readRecord(BinaryReader reader) throws IOException, OmfException {
		OmfRecord res = null;
		byte type = reader.peekNextByte();
		type &= 0xfe;	// Mask off the least significant bit
		switch(type) {
		case THEADR:
		case LHEADR:
			res = new OmfFileHeader(reader);
			break;
		case COMENT:
			res = new OmfCommentRecord(reader);
			break;
		case MODEND:
			res = new OmfModuleEnd(reader);
			break;
		case EXTDEF:
			res = new OmfExternalSymbol(reader,false);
			break;
		case PUBDEF:
			res = new OmfSymbolRecord(reader,false);
			break;
		case LINNUM:
			res = new OmfLineNumberRecord(reader);
			break;
		case LNAMES:
			res = new OmfNamesRecord(reader);
			break;
		case SEGDEF:
			res = new OmfSegmentHeader(reader);
			break;
		case GRPDEF:
			res = new OmfGroupRecord(reader);
			break;
		case FIXUPP:
			res = new OmfFixupRecord(reader);
			break;
		case LEDATA:
			res = new OmfEnumeratedData(reader);
			break;
		case LIDATA:
			res = new OmfIteratedData(reader);
			break;
		case COMDEF:
			res = new OmfComdefRecord(reader,false);
			break;
		case LEXTDEF:
			res = new OmfExternalSymbol(reader,true);
			break;
		case LPUBDEF:
			res = new OmfSymbolRecord(reader,true);
			break;
		case LCOMDEF:
			res = new OmfComdefRecord(reader,true);
			break;
		default:
			throw new OmfException("Unrecognized record type");
		}
		return res;
	}
	
	/**
	 * Read the OMF string format,  1-byte length, followed by that many ascii characters
	 * @param reader
	 * @return
	 * @throws IOException 
	 */
	public static String readString(BinaryReader reader) throws IOException {
		int count = reader.readNextByte() & 0xff;
		return reader.readNextAsciiString(count);
	}
}
