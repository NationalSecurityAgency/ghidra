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
package ghidra.app.services;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import javax.swing.tree.TreePath;

import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.HelpLocation;

/**
 * A stub of the {@link DataTypeManagerService} interface.  This can be used to supply a test values 
 * or to spy on system internals by overriding methods as needed.
 */
public class TestDoubleDataTypeManagerService implements DataTypeManagerService {

	@Override
	public DataTypeManager[] getDataTypeManagers() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getSortedDataTypeList() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(String filterText) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager getBuiltInDataTypesManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getFavorites() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRecentlyUsed(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getRecentlyUsed() {
		throw new UnsupportedOperationException();
	}

	@Override
	public HelpLocation getEditorHelpLocation(DataType dataType) {
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
	public void closeArchive(DataTypeManager dtm) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Archive openArchive(DataTypeArchive dataTypeArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Archive openArchive(File file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDataTypeSelected(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(TreePath selectedPath) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<String> getPossibleEquateNames(long value) {
		throw new UnsupportedOperationException();
	}
}
