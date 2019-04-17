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
package ghidra.file.formats.bplist;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class NSDictionary extends NSObject {

	private List<Integer> keys = new ArrayList<Integer>();
	private List<Integer> values = new ArrayList<Integer>();

	private int objectRefSize;

	public NSDictionary(int objectRefSize) {
		this.objectRefSize = objectRefSize;
	}

	@Override
	public String getType() {
		return "NSDictionary";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("NSDictionary_" + keys.size(), 0);
		addHeader(structure, keys.size());
		for (int i = 0; i < keys.size(); ++i) {
			if (objectRefSize == 1) {
				structure.add(BYTE, "key" + i, null);
				structure.add(BYTE, "value" + i, null);
			}
			else if (objectRefSize == 2) {
				structure.add(WORD, "key" + i, null);
				structure.add(WORD, "value" + i, null);
			}
			else if (objectRefSize == 4) {
				structure.add(DWORD, "key" + i, null);
				structure.add(DWORD, "value" + i, null);
			}
			else if (objectRefSize == 8) {
				structure.add(QWORD, "key" + i, null);
				structure.add(QWORD, "value" + i, null);
			}
			else {
				throw new RuntimeException();
			}
		}
		return structure;
	}

	public void put(int key, int value) {
		keys.add(key);
		values.add(value);
	}

	@Override
	public void markup(Data objectData, Program program, TaskMonitor monitor)
			throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		for (int i = 0; i < objectData.getNumComponents(); ++i) {
			monitor.checkCanceled();
			Data component = objectData.getComponent(i);
			if (component.getFieldName().startsWith("key") ||
				component.getFieldName().startsWith("value")) {
				long value = getValue(component);
				String name = BinaryPropertyListUtil.generateName(value);
				Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, name,
					err -> Msg.error(this, err));
				if (symbol != null) {
					referenceManager.addMemoryReference(component.getMinAddress(),
						symbol.getAddress(), RefType.DATA, SourceType.ANALYSIS, 0);
				}
			}
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("NSDictionary {");
		for (int i = 0; i < keys.size(); ++i) {
			builder.append("{0x" + Integer.toHexString(keys.get(i)) + ",0x" +
				Integer.toHexString(values.get(i)) + "}");
		}
		builder.append("}");
		return builder.toString();
	}
}
