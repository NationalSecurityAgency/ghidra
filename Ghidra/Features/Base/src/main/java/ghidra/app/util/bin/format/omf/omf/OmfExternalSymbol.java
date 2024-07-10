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

public class OmfExternalSymbol extends OmfRecord {

	private boolean isStatic;
	protected List<OmfSymbol> symbols = new ArrayList<>();
	
	private record Reference(OmfString name, OmfIndex type) {}

	private List<Reference> refs = new ArrayList<>();

	public OmfExternalSymbol(BinaryReader reader, boolean isStatic) throws IOException {
		super(reader);
		this.isStatic = isStatic;
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			OmfString name = OmfUtils.readString(dataReader);
			OmfIndex type = OmfUtils.readIndex(dataReader);
			refs.add(new Reference(name, type));
			symbols.add(new OmfSymbol(name.str(), type.value(), 0, 0, 0));
		}
	}

	public List<OmfSymbol> getSymbols() {
		return symbols;
	}

	public boolean isStatic() {
		return isStatic;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(OmfRecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		for (Reference ref : refs) {
			struct.add(ref.name.toDataType(), "name", null);
			struct.add(ref.type.toDataType(), "type", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}
