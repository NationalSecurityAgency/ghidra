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
import java.util.*;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class NSSet extends NSObject {

	private boolean ordered;
	private int objectRefSize;

	private Set<Integer> set;

	public NSSet(boolean ordered, int objectRefSize) {
		this.ordered = ordered;
		this.objectRefSize = objectRefSize;
		if (ordered) {
			set = new TreeSet<Integer>();
		}
		else {
			set = new LinkedHashSet<Integer>();
		}
	}

	@Override
	public String getType() {
		return "NSSet";
	}

	public boolean isOrdered() {
		return ordered;
	}

	public Set<Integer> getSet() {
		return set;
	}

	public void add(int object) {
		set.add(object);
	}

	@Override
	public void markup(Data objectData, Program program, TaskMonitor monitor)
			throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		for (int i = 0; i < objectData.getNumComponents(); ++i) {
			monitor.checkCanceled();
			Data component = objectData.getComponent(i);
			if (component.getFieldName().startsWith("value")) {
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
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("NSSet_" + set.size(), 0);
		addHeader(structure, set.size());
		for (int i = 0; i < set.size(); ++i) {
			if (objectRefSize == 1) {
				structure.add(BYTE, "value_" + i, null);
			}
			else if (objectRefSize == 2) {
				structure.add(WORD, "value_" + i, null);
			}
			else if (objectRefSize == 4) {
				structure.add(DWORD, "value_" + i, null);
			}
			else if (objectRefSize == 8) {
				structure.add(QWORD, "value_" + i, null);
			}
			else {
				throw new RuntimeException();
			}
		}
		return structure;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("{");
		for (Integer object : set) {
			builder.append(" ");
			builder.append("0x" + Integer.toHexString(object));
			builder.append(",");
		}
		builder.deleteCharAt(builder.length() - 1);// pop last comma
		builder.append(" ");
		builder.append("}");
		return builder.toString();
	}

}
