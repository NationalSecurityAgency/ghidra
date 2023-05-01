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
package ghidra.app.plugin.core.analysis;

import java.util.List;
import java.util.Set;

import javax.swing.tree.TreePath;

import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.app.plugin.core.datamgr.archive.DefaultDataTypeArchiveService;
import ghidra.app.plugin.core.datamgr.util.DataTypeComparator;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManagerChangeListener;
import ghidra.util.HelpLocation;

// FIXME!! TESTING
public class DefaultDataTypeManagerService extends DefaultDataTypeArchiveService
		implements DataTypeManagerService {

	// TODO: This implementation needs to be consolidated with the tool-based service in 
	// favor of a single static data type manager service used by both the tool and 
	// headless scenarios

	@Override
	public HelpLocation getEditorHelpLocation(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEditable(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void edit(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(String filterText) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(TreePath selectedTreeNode) {
		if (selectedTreeNode == null) {
			return null;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getFavorites() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getRecentlyUsed() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getSortedDataTypeList() {
		List<DataType> dataTypes =
			builtInDataTypesManager.getDataTypes(BuiltInSourceArchive.INSTANCE);
		dataTypes.sort(new DataTypeComparator());
		return dataTypes;
//		throw new UnsupportedOperationException();
	}

	@Override
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDataTypeSelected(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getSelectedDatatypes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRecentlyUsed(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<String> getPossibleEquateNames(long value) {
		throw new UnsupportedOperationException();
	}
}
