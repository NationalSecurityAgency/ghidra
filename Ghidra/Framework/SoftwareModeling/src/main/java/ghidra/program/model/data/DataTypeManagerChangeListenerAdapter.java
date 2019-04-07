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
package ghidra.program.model.data;

import ghidra.app.plugin.core.datamgr.archive.SourceArchive;

/**
 * Adapter for a Category change listener.
 */
public class DataTypeManagerChangeListenerAdapter implements DataTypeManagerChangeListener {

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#categoryAdded(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#categoryMoved(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#categoryRemoved(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
	}

	/** 
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#categoryRenamed(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#dataTypeAdded(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#dataTypeChanged(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#dataTypeMoved(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#dataTypeRemoved(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#dataTypeRenamed(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#dataTypeReplaced(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath, ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath,
			DataType newDataType) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManagerChangeListener#favoritesChanged(ghidra.program.model.data.DataTypeManager, ghidra.program.model.data.CategoryPath, boolean)
	 */
	@Override
	public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
	}

	@Override
	public void sourceArchiveAdded(DataTypeManager dataTypeManager, SourceArchive dataTypeSource) {
	}

	@Override
	public void sourceArchiveChanged(DataTypeManager dataTypeManager, SourceArchive dataTypeSource) {
	}

}
