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

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.HelpLocation;

/**
 * Service to provide list of cycle groups and data types identified as
 * "favorites." Favorites will show up on the popup menu for creating
 * data and defining function return types and parameters.
 */
@ServiceInfo(defaultProvider = DataTypeManagerPlugin.class, description = "Service to provide list of cycle groups and data types identified as 'Favorites.'")
public interface DataTypeManagerService extends DataTypeQueryService {

	/**
	 * Get the data type manager that has all of the built in types.
	 * @return data type manager for built in data types
	 */
	public DataTypeManager getBuiltInDataTypesManager();

	/**
	 * Get the data types marked as favorites that will show up on
	 * a popup menu.
	 * @return list of favorite datatypess
	 */
	public List<DataType> getFavorites();

	/**
	 * Adds a listener to be notified when changes occur to any open datatype manager.
	 * @param listener the listener to be added.
	 */
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener);

	/**
	 * Removes the given listener from receiving dataTypeManger change notifications.
	 * @param listener the listener to be removed.
	 */
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener);

	/**
	 * Set the given data type as the most recently used to apply a
	 * data type to a Program.
	 * @param dt data type that was most recently used
	 */
	public void setRecentlyUsed(DataType dt);

	/**
	 * Get the data type that was most recently used to apply data to a
	 * Program.
	 * @return data type that was most recently used
	 */
	public DataType getRecentlyUsed();

	/**
	 * Gets the location of the help for editing the specified data type.
	 * @param dataType the data type to be edited.
	 * @return the help location for editing the data type.
	 */
	public HelpLocation getEditorHelpLocation(DataType dataType);

	/**
	 * Determine if the indicated data type can be edited 
	 * (i.e. it has an editor that this service knows how to invoke).
	 * @param dt data type to be edited
	 * @return true if this service can invoke an editor for changing the data type.
	 */
	public boolean isEditable(DataType dt);

	/**
	 * Pop up an editor dialog for the given data type.
	 * 
	 * @param dt data type that either a Structure or a Union; built in types cannot be edited
	 * @throws IllegalArgumentException if the given has not been resolved by a DataTypeManager;
	 *         in other words, if {@link DataType#getDataTypeManager()} returns null.
	 */
	public void edit(DataType dt);

	/**
	 * Closes the archive for the given {@link DataTypeManager}.  This will ignore request to 
	 * close the open Program's manager and the built-in manager.  
	 * 
	 * @param dtm the data type manager of the archive to close
	 */
	public void closeArchive(DataTypeManager dtm);

	/**
	 * Opens the specified data type archive contained within the Ghidra installation.
	 * NOTE: This is predicated upon all archive files having a unique name within the installation.
	 * Any path prefix specified may prevent the file from opening (or reopening) correctly.
	 * @param archiveName archive file name (i.e., "generic_C_lib")
	 * @return the data type archive or null if an archive with the specified name
	 * can not be found.
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 */
	public DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException;

	/** 
	 * A method to open an Archive for the given, pre-existing DataTypeArchive (like one that
	 * was opened during the import process.
	 * 
	 * @param dataTypeArchive the archive from which to create an Archive
	 * @return an Archive based upon the given DataTypeArchive
	 */
	public Archive openArchive(DataTypeArchive dataTypeArchive);

	/**
	 * A method to open an Archive for the given, pre-existing archive file (*.gdt)
	 * 
	 * @param file data type archive file
	 * @param acquireWriteLock true if write lock should be acquired (i.e., open for update)
	 * @return an Archive based upon the given archive files
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 */
	public Archive openArchive(File file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException;

	/**
	 * Selects the given data type in the display of data types.  A null <code>dataType</code>
	 * value will clear the current selection.
	 * 
	 * @param dataType The data type to select.
	 */
	public void setDataTypeSelected(DataType dataType);

	/**
	 * Shows the user a dialog that allows them to choose a data type from a tree of all available
	 * data types.
	 * 
	 * @param selectedPath An optional tree path to select in the tree
	 * @return A data type chosen by the user
	 */
	public DataType getDataType(TreePath selectedPath);

	/**
	 * Examines all enum dataTypes for items that match the given value. Returns a list of Strings
	 * that might make sense for the given value.
	 * @param value the value to search for.
	 * @return the list of enum item names that match the given value
	 */
	public Set<String> getPossibleEquateNames(long value);
}
