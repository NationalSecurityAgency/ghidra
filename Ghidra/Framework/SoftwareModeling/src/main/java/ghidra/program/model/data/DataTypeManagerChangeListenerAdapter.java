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

/**
 * Adapter for a Category change listener.
 */
public class DataTypeManagerChangeListenerAdapter implements DataTypeManagerChangeListener {

	@Override
	public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
	}

	@Override
	public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
	}

	@Override
	public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
	}

	@Override
	public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
	}

	@Override
	public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
	}

	@Override
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
	}

	@Override
	public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
	}

	@Override
	public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
	}

	@Override
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
	}

	@Override
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath,
			DataType newDataType) {
	}

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
