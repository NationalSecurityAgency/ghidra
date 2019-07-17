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

public class OmfComdefRecord extends OmfExternalSymbol {

	public OmfComdefRecord(BinaryReader reader,boolean isStatic) throws IOException, OmfException {
		super(isStatic);
		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;

		ArrayList<OmfSymbol> symbollist = new ArrayList<OmfSymbol>();
		while(reader.getPointerIndex() < max) {
			String name = OmfRecord.readString(reader);
			int typeIndex = OmfRecord.readIndex(reader);
			byte dataType = reader.readNextByte();
			int byteLength=0;
			if (dataType == 0x61) {		// FAR data, reads numElements and elSize
				int numElements = readCommunalLength(reader);
				int elSize = readCommunalLength(reader);
				byteLength = numElements * elSize;
			}
			else {
				// Values 1 thru 5f plus 61, read the byte length
				byteLength = readCommunalLength(reader);
			}
			OmfSymbol sym = new OmfSymbol(name,typeIndex,0,dataType,byteLength);
			symbollist.add(sym);
		}
		readCheckSumByte(reader);
		symbol = new OmfSymbol[symbollist.size()];
		symbollist.toArray(symbol);
	}
	
	private static int readCommunalLength(BinaryReader reader) throws OmfException, IOException {
		int val = reader.readNextByte() & 0xff;
		if (val <= 128)
			return val;
		if (val == 0x81) {
			val = reader.readNextShort() & 0xffff;
		}
		else if (val == 0x84) {
			val = reader.readNextShort() & 0xffff;
			int hithird = reader.readNextByte() & 0xff;
			val += (hithird << 16);
		}
		else if (val == 0x88) {
			val = reader.readNextInt();
		}
		else
			throw new OmfException("Illegal communal length encoding");
		return val;
	}
		
}
