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

public class OmfComdatExternalSymbol extends OmfExternalSymbol {
	
	public record ExternalLookup(int nameIndex, int type) {}
	protected List<ExternalLookup> externalLookups = new ArrayList<>();

	private record Reference(OmfIndex nameIndex, OmfIndex typeIndex) {}
	private List<Reference> refs = new ArrayList<>();

	public OmfComdatExternalSymbol(BinaryReader reader) throws IOException {
		super(reader, false);

	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			OmfIndex nameIndex = OmfUtils.readIndex(dataReader);
			OmfIndex type = OmfUtils.readIndex(dataReader);
			refs.add(new Reference(nameIndex, type));
			externalLookups.add(new ExternalLookup(nameIndex.value(), type.value()));
		}
	}

	public void loadNames(List<String> nameList) {
		for (ExternalLookup ext : externalLookups) {
			String name = nameList.get(ext.nameIndex - 1);
			symbols.add(new OmfSymbol(name, ext.type, 0, 0, 0));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(OmfRecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		for (Reference ref : refs) {
			struct.add(ref.nameIndex.toDataType(), "logical_name_index", null);
			struct.add(ref.typeIndex.toDataType(), "type_index", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}
