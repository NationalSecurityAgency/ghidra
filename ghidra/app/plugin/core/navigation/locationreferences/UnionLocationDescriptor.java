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
package ghidra.app.plugin.core.navigation.locationreferences;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A location descriptor to find references to a Union data type.
 */
class UnionLocationDescriptor extends DataTypeLocationDescriptor {

	private Union union;

	UnionLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		// Note: we pass null for the 'fieldName', as we have no way of disambiguating which 
		//       field a reference will point to. So, grab all references.

		String fieldName = null;
		ReferenceUtils.findDataTypeReferences(accumulator, union, fieldName, program,
			useDynamicSearching, monitor);
	}

	@Override
	protected String generateLabel() {
		return getDataTypeName();
	}

	@Override
	protected DataType getSourceDataType() {
		Data data = getData(getLocation());
		Data parentData = getParent(data);
		DataType dataType = parentData.getDataType();
		if (!(dataType instanceof Union)) {
			throw new AssertException("A Union is required for this LocationDescriptor");
		}
		union = (Union) dataType;
		return dataType;
	}

	private Data getParent(Data data) {
		Data parent = data.getParent();
		if (parent == null) {
			return data;
		}

		Data nextParent = getParent(parent);
		if (nextParent != null) {
			return nextParent;
		}
		return data;
	}

	@Override
	protected String getDataTypeName() {
		return union.getDisplayName();
	}
}
