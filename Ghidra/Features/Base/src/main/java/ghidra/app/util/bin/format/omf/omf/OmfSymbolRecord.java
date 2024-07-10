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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class OmfSymbolRecord extends OmfRecord {
	private OmfIndex baseGroupIndex;
	private OmfIndex baseSegmentIndex;
	private int baseFrame;
	private boolean isStatic;
	private OmfSymbol[] symbol;
	private List<Reference> refs = new ArrayList<>();

	private record Reference(OmfString name, Omf2or4 offset, OmfIndex type) {}

	public OmfSymbolRecord(BinaryReader reader, boolean isStatic) throws IOException {
		super(reader);
		this.isStatic = isStatic;
	}

	@Override
	public void parseData() throws IOException {
		boolean hasBigFields = hasBigFields();
		baseGroupIndex = OmfUtils.readIndex(dataReader);
		baseSegmentIndex = OmfUtils.readIndex(dataReader);
		if (baseSegmentIndex.value() == 0) {
			baseFrame = dataReader.readNextUnsignedShort();
		}

		ArrayList<OmfSymbol> symbollist = new ArrayList<OmfSymbol>();
		while (dataReader.getPointerIndex() < dataEnd) {
			OmfString name = OmfUtils.readString(dataReader);
			Omf2or4 offset = OmfUtils.readInt2Or4(dataReader, hasBigFields);
			OmfIndex type = OmfUtils.readIndex(dataReader);
			OmfSymbol subrec = new OmfSymbol(name.str(), type.value(), offset.value(), 0, 0);
			symbollist.add(subrec);
			refs.add(new Reference(name, offset, type));
		}
		symbol = new OmfSymbol[symbollist.size()];
		symbollist.toArray(symbol);
	}

	public boolean isStatic() {
		return isStatic;
	}

	public int getGroupIndex() {
		return baseGroupIndex.value();
	}

	public int getSegmentIndex() {
		return baseSegmentIndex.value();
	}

	public int numSymbols() {
		return symbol.length;
	}

	public OmfSymbol getSymbol(int i) {
		return symbol[i];
	}

	public List<OmfSymbol> getSymbols() {
		return List.of(symbol);
	}

	public int getBaseFrame() {
		return baseFrame;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(OmfRecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		struct.add(baseGroupIndex.toDataType(), "base_group_index", null);
		struct.add(baseSegmentIndex.toDataType(), "base_segment_index", null);
		if (baseSegmentIndex.value() == 0) {
			struct.add(WORD, "base_frame", null);
		}
		for (Reference ref : refs) {
			struct.add(ref.name.toDataType(), "name", null);
			struct.add(ref.offset.toDataType(), "offset", null);
			struct.add(ref.type.toDataType(), "type", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}
