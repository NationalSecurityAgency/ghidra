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
 * The listener interface for notification of changes to a DataTypeManager
 */
public interface DataTypeManagerChangeListener {

	/**
	 * Notification when category is added.
	 * @param dtm the dataType manager
	 * @param path the categoryPath of the newly added category.
	 */
	public void categoryAdded(DataTypeManager dtm, CategoryPath path);

	/**
	 * Notification when a category is removed.
	 * @param dtm data type manager associated with the category
	 * @param path the categoryPath of the category that was removed.
	 */
	public void categoryRemoved(DataTypeManager dtm, CategoryPath path);

	/**
	 * Notification when category is renamed.
	 * @param dtm data type manager associated with the category
	 * @param oldPath the path of the category before it was renamed.
	 * @param newPath the path of the category after it was renamed.  This path will only differ in
	 * the last segment of the path.
	 */
	public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath);

	/**
	 * Notification when a category is reparented to new category.  
	 * @param dtm data type manager associated with the category
	 * @param oldPath the path of the category before it was moved.
	 * @param newPath the path of the category after it was moved.
	 */
	public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath);

	/**
	 * Notification when a data type is added to a category
	 * @param dtm data type manager for the given category paths.
	 * @param path the DataTypePath of the newly added datatype.
	 */
	public void dataTypeAdded(DataTypeManager dtm, DataTypePath path);

	/**
	 * Notification when data type is removed.
	 * @param dtm data type manager for the given category paths.
	 * @param path the DataTypePath of the removed datatype.
	 */
	public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path);

	/**
	 * Notification when data type is renamed.
	 * @param dtm data type manager for the given category paths.
	 * @param oldPath the path of the datatype before it was renamed.
	 * @param newPath the path of the datatype after it was renamed.
	 */
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath);

	/**
	 * Notification when a data type is moved.
	 * @param dtm data type manager for the given category paths.
	 * @param oldPath the path of the datatype before it was moved.
	 * @param newPath the path of the datatype after it was moved.
	 */
	public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath);

	/**
	 * Notification when data type is changed.
	 * @param dtm data type manager for the given category paths.
	 * @param path the path of the datatype that changed.
	 */
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path);

	/**
	 * Notification when a data type has been replaced.
	 * @param dtm data type manager for the given category paths.
	 * @param oldPath the path of the datatype that was replaced.
	 * @param newPath the path of the datatype that replaced the existing datatype.
	 * @param newDataType the new dataType that replaced the old dataType
	 */
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath,
			DataType newDataType);

	/**
	 * Notification the favorite status of a datatype has changed
	 * @param dtm data type manager for the given category paths.
	 * @param path the DataTypePath of the datatype had its favorite status changed.
	 * @param isFavorite reflects the current favorite status of the datatype.
	 */
	public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite);

	/**
	 * Notification that the information for a particular source archive has changed. Typically,
	 * this would be because it was renamed or moved.
	 * @param dataTypeManager data type manager referring to the given source information.
	 * @param sourceArchive the changed data type source information
	 */
	public void sourceArchiveChanged(final DataTypeManager dataTypeManager,
			final SourceArchive sourceArchive);

	/**
	 * Notification that the information for a source archive has been added. This happens when
	 * a data type from the indicated source archive is added to this data type manager.
	 * @param dataTypeManager data type manager referring to the given source information.
	 * @param sourceArchive the new data type source information
	 */
	public void sourceArchiveAdded(final DataTypeManager dataTypeManager,
			final SourceArchive sourceArchive);
}
