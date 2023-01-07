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

public class OmfComdatExternalSymbol extends OmfExternalSymbol {
	public static class ExternalLookup {
		public int nameIndex;
		public int type;
		
		public ExternalLookup(int ni, int t) {
			this.nameIndex = ni;
			this.type = t;
		}
		
	}
	
	protected ArrayList<ExternalLookup> externalLookups;
	protected OmfSymbol[] symbol;

	public OmfComdatExternalSymbol(BinaryReader reader) throws IOException {
		super(false);
		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		this.externalLookups = new ArrayList<ExternalLookup>();
		
		while(reader.getPointerIndex() < max) {
			int nameIndex = OmfRecord.readIndex(reader);
			int type = OmfRecord.readIndex(reader);
			this.externalLookups.add(new ExternalLookup(nameIndex, type));
		}
		
		readCheckSumByte(reader);
	}

	public void loadNames(ArrayList<String> namelist) {
		ArrayList<OmfSymbol> symbollist = new ArrayList<OmfSymbol>();
		for (ExternalLookup ext : this.externalLookups) {
			String name = namelist.get(ext.nameIndex-1);
			symbollist.add(new OmfSymbol(name, ext.type, 0, 0, 0));
		}
		this.symbol = new OmfSymbol[symbollist.size()];
		symbollist.toArray(this.symbol);
	}
	
	public OmfSymbol[] getSymbols() {
		return symbol;
	}
}
