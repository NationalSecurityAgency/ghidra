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
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class OmfSymbolRecord extends OmfRecord {
	private int baseGroupIndex;
	private int baseSegmentIndex;
	private int baseFrame;
	private boolean isStatic;
	private OmfSymbol[] symbol;
	
	public OmfSymbolRecord(BinaryReader reader,boolean isStatic) throws IOException {
		this.isStatic = isStatic;
		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		boolean hasBigFields = hasBigFields();
		baseGroupIndex = OmfRecord.readIndex(reader);
		baseSegmentIndex = OmfRecord.readIndex(reader);
		if (baseSegmentIndex == 0)
			baseFrame = reader.readNextShort() & 0xffff;
		
		ArrayList<OmfSymbol> symbollist = new ArrayList<OmfSymbol>();
		while(reader.getPointerIndex() < max) {
			String name = OmfRecord.readString(reader);
			long offset = OmfRecord.readInt2Or4(reader, hasBigFields) & 0xffffffffL;
			int type = OmfRecord.readIndex(reader);
			OmfSymbol subrec = new OmfSymbol(name,type,offset,0,0);
			symbollist.add(subrec);
		}
		readCheckSumByte(reader);
		symbol = new OmfSymbol[symbollist.size()];
		symbollist.toArray(symbol);
	}

	public boolean isStatic() {
		return isStatic;
	}
	
	public int getGroupIndex() {
		return baseGroupIndex;
	}
	
	public int getSegmentIndex() {
		return baseSegmentIndex;
	}
	
	public int numSymbols() {
		return symbol.length;
	}
	
	public OmfSymbol getSymbol(int i) {
		return symbol[i];
	}
}
