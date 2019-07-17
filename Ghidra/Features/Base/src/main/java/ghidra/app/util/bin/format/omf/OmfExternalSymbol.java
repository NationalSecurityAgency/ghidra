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

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;
import java.util.ArrayList;

public class OmfExternalSymbol extends OmfRecord {
	private boolean isStatic;
	protected OmfSymbol[] symbol;
	
	protected OmfExternalSymbol(boolean isStatic) {
		this.isStatic = isStatic;
	}
	
	public OmfExternalSymbol(BinaryReader reader,boolean isStatic) throws IOException {
		this.isStatic = isStatic;
		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		ArrayList<OmfSymbol> symbollist = new ArrayList<OmfSymbol>();
		
		while(reader.getPointerIndex() < max) {
			String name = OmfRecord.readString(reader);
			int type = OmfRecord.readIndex(reader);
			OmfSymbol subrec = new OmfSymbol(name,type,0,0,0);
			symbollist.add(subrec);
		}
		
		readCheckSumByte(reader);
		symbol = new OmfSymbol[symbollist.size()];
		symbollist.toArray(symbol);
	}

	public OmfSymbol[] getSymbols() {
		return symbol;
	}
	
	public boolean isStatic() {
		return isStatic;
	}
}
