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
package ghidra.app.plugin.core.data;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.DataTypeProviderContext;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.util.ArrayList;

public class ProgramStructureProviderContext implements DataTypeProviderContext {
	Program program;
	Address addr;
	Structure struct = null;
	int myoffset;

	public ProgramStructureProviderContext(Program program, ProgramLocation loc) {
		this.program = program;

		int dataPath[] = loc.getComponentPath();
		Data data = program.getListing().getDefinedDataContaining(loc.getAddress());
		data = data.getComponent(dataPath);
		this.addr = data.getMinAddress();
		myoffset = data.getParentOffset();
		data = data.getParent();
		struct = (Structure) data.getDataType();
	}

	public ProgramStructureProviderContext(Program program, Address addr, Structure struct,
			int myOffset) {
		this.program = program;
		this.addr = addr;
		this.struct = struct;
		this.myoffset = myOffset;
	}

	@Override
	public DataTypeComponent getDataTypeComponent(int offset) {
		int poffset = myoffset + offset;

		if (poffset < 0 || poffset >= struct.getLength()) {
			return null;

		}
		return struct.getComponentAt(poffset);
	}

	/**
	 * Get an array of CodePrototypes that begin at or after start up to end.
	 *   Prototypes that exist before start are not returned
	 *   Prototypes that exist before end, but terminate after end ARE returned
	 *   The prototypes must be contiguous from start to end
	 *
	 * @param start start offset
	 * @param end end offset
	 *
	 * @return array of CodePrototypes that exist between start and end.
	 */
	@Override
	public DataTypeComponent[] getDataTypeComponents(int start, int end) {
		ArrayList<DataTypeComponent> list = new ArrayList<DataTypeComponent>();
		for (int offset = start; offset <= end;) {
			DataTypeComponent dtc = getDataTypeComponent(offset);
			if (dtc == null) {
				break;
			}
			list.add(dtc);
			offset += dtc.getLength();
		}
		DataTypeComponent[] dataTypeComps = new DataTypeComponent[list.size()];
		return list.toArray(dataTypeComps);
	}

	@Override
	public String getUniqueName(String baseName) {
		return program.getListing().getDataTypeManager().getUniqueName(CategoryPath.ROOT, baseName);
	}

}
