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
package ghidra.app.plugin.core.datamgr.tree;

import java.util.Collections;
import java.util.List;

import docking.DefaultActionContext;
import ghidra.app.plugin.core.datamgr.DataTypeContext;
import ghidra.program.model.data.DataType;

public class DataTypeTableContext extends DefaultActionContext implements DataTypeContext {

	private List<DataType> selectedTypes;

	DataTypeTableContext(DataTypesTableProvider provider, List<DataType> selectedTypes) {
		super(provider, provider.getTable());
		this.selectedTypes = selectedTypes;
	}

	@Override
	public DataType getSelectedDataType() {
		if (selectedTypes.size() == 1) {
			return selectedTypes.get(0);
		}
		return null;
	}

	@Override
	public List<DataType> getSelectedDataTypes() {
		return Collections.unmodifiableList(selectedTypes);
	}

	@Override
	public boolean hasSelectedDataTypes() {
		return !selectedTypes.isEmpty();
	}
}
