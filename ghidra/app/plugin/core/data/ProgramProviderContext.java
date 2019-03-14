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

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.DataTypeProviderContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;

public class ProgramProviderContext implements DataTypeProviderContext {
	Program program;

	Address addr;

	public ProgramProviderContext(Program program, Address addr) {
		this.program = program;
		this.addr = addr;
	}

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
		return list.toArray(new DataTypeComponent[list.size()]);
	}

	@Override
	public DataTypeComponent getDataTypeComponent(int offset) {
		Data data = getData(offset);
		if (data == null) {
			return null;
		}

		DataType dt = data.getDataType();
		int length = data.getLength();
		String label = null;
		Symbol symbol = data.getPrimarySymbol();
		if (symbol != null && !symbol.isDynamic()) {
			label = symbol.getName();
		}
		String comment = data.getComment(CodeUnit.EOL_COMMENT);
		return new DataTypeComponentImpl(dt, null, length, 0, offset, label, comment);

	}

	private Data getData(int offset) {
		Address offAddr = addr.addWrap(offset);

		return program.getListing().getDataAt(offAddr);
	}

	@Override
	public String getUniqueName(String baseName) {
		return program.getListing().getDataTypeManager().getUniqueName(CategoryPath.ROOT, baseName);
	}

}
