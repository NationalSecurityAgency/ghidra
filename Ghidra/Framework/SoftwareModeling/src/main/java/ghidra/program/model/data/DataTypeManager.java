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

import java.util.*;

import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for Managing data types.
 */
public interface DataTypeManager {

	/**
	 * ID for the default (undefined) data type.
	 */
	public static long DEFAULT_DATATYPE_ID = 0;

	/**
	 * ID if data type type is not known in this data type manager.
	 */
	public static long NULL_DATATYPE_ID = -1;

	/**
	 * ID if data type type is BAD.
	 */
	public static long BAD_DATATYPE_ID = -2;

	/**
	 * Name of the category for the build in data types.
	 */
	public final static String BUILT_IN_DATA_TYPES_NAME = "BuiltInTypes";

	public final long LOCAL_ARCHIVE_KEY = 0;
	public final long BUILT_IN_ARCHIVE_KEY = 1;
	public final UniversalID LOCAL_ARCHIVE_UNIVERSAL_ID = new UniversalID(LOCAL_ARCHIVE_KEY);
	public final UniversalID BUILT_IN_ARCHIVE_UNIVERSAL_ID = new UniversalID(BUILT_IN_ARCHIVE_KEY);

	/**
	 * Returns the universal ID for this dataType manager
	 * @return the universal ID for this dataType manager
	 */
	public UniversalID getUniversalID();

	/**
	 * Returns true if the given category path exists in this datatype manager
	 * @param path the path
	 * @return true if the given category path exists in this datatype manager
	 */
	public boolean containsCategory(CategoryPath path);

	/**
	 * Returns a unique name not currently used by any other dataType or category
	 * with the same baseName
	 * 
	 * @param path the path of the name
	 * @param baseName the base name to be made unique
	 * @return a unique name starting with baseName
	 */
	public String getUniqueName(CategoryPath path, String baseName);

	/**
	 * Returns a dataType that is "in" (ie suitable implementation) this
	 * Manager, creating a new one if necessary.  Also the returned dataType
	 * will be in a category in this dataTypeManager that is equivalent to the
	 * category of the passed in dataType.
	 * @param dataType the dataType to be resolved.
	 * @param handler used to resolve conflicts with existing dataTypes.
	 * @return an equivalent dataType that "belongs" to this dataTypeManager.
	 */
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler);

	/**
	 * Returns a data type after adding it to this data manager.
	 * The returned dataType will be in a category in this dataTypeManager
	 * that is equivalent to the category of the passed in dataType.
	 * 
	 * @param dataType the dataType to be resolved.
	 * @param handler used to resolve conflicts with existing dataTypes.
	 * @return an equivalent dataType that "belongs" to this dataTypeManager.
	 */
	public DataType addDataType(DataType dataType, DataTypeConflictHandler handler);

	/**
	 * Sequentially adds a collection of datatypes to this data manager.
	 * This method provides the added benefit of equivalence caching
	 * for improved performance.
	 * <br>
	 * WARNING: This is an experimental method whose use may cause the GUI and
	 * task monitor to become unresponsive due to extended hold times on the manager lock.
	 * @param dataTypes collection of datatypes
	 * @param handler conflict handler
	 * @param monitor task monitor
	 * @throws CancelledException if monitor is cancelled
	 */
	public void addDataTypes(Collection<DataType> dataTypes, DataTypeConflictHandler handler,
			TaskMonitor monitor) throws CancelledException;

	/**
	 * Returns an iterator over all the dataTypes in this manager
	 * @return an iterator over all the dataTypes in this manager
	 */
	public Iterator<DataType> getAllDataTypes();

	/**
	 * Adds all data types to the specified list.]
	 * 
	 * @param list the result list into which the types will be placed
	 */
	public void getAllDataTypes(List<DataType> list);

	/**
	 * Returns an iterator over all structures in this manager
	 * @return the iterator
	 */
	public Iterator<Structure> getAllStructures();

	/**
	 * Returns an iterator over all composite data types (structures and unions) in this manager
	 * @return the iterator
	 */
	public Iterator<Composite> getAllComposites();

	/**
	 * Begin searching at the root category for all data types with the
	 * given name. Places all the data types in this data type manager
	 * with the given name into the list.
	 * @param name name of the data type
	 * @param list list that will be populated with matching DataType objects
	 */
	public void findDataTypes(String name, List<DataType> list);

	/**
	 * Begin searching at the root category for all data types with names
	 * that match the given name that may contain wildcards.
	 * @param name name to match; may contain wildcards
	 * @param list list that will be populated with matching DataType objects
	 * @param caseSensitive true if the match is case sensitive
	 * @param monitor task monitor to cancel the search
	 */
	public void findDataTypes(String name, List<DataType> list, boolean caseSensitive,
			TaskMonitor monitor);

	/**
	 * Replace an existing dataType with another.  All instances and references will be updated to
	 * use the replacement dataType.
	 * @param existingDt the dataType to be replaced.
	 * @param replacementDt the dataType to use as the replacement.
	 * @param updateCategoryPath if true, the replacementDt will have its categoryPath changed
	 * to the exitingDt's path.
	 * @return the resolved replacement dataType.
	 * @throws DataTypeDependencyException if the replacement datatype depends on
	 * the existing dataType;
	 */
	public DataType replaceDataType(DataType existingDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException;

	/**
	 * Retrieve the data type with the fully qualified path. So you can get the data named
	 * "bar" in the category "foo" by calling getDataType("/foo/bar").  This method can
	 * be problematic now that datatype names can contain slashes.  It will work provided
	 * that the part of the datatype name that precedes its internal slash is not also the
	 * name of a category in the same category as the datatype.  For example, if you call
	 * getDataType("/a/b/c"), and "b/c" is the name of your datatype, it will find it unless
	 * there is also a category "b" under category "a".  A better solution is to use
	 * the {@link #getDataType(DataTypePath)} method because the DataTypePath keeps the
	 * category and datatype name separate.
	 * 
	 * @param dataTypePath path
	 * @return the dataType or null if it isn't found
	 */
	public DataType getDataType(String dataTypePath);

	/**
	 * Gets the dataType for the given path. See {@link #getDataType(String)} for details.
	 * @param dataTypePath dataType path
	 * @return dataType at the given path
	 * @deprecated use {@link #getDataType(String)} or better yet {@link #getDataType(DataTypePath)}
	 */
	@Deprecated
	public DataType findDataType(String dataTypePath);

	/**
	 * Find the dataType for the given dataTypePath.
	 * @param dataTypePath the DataTypePath for the datatype
	 * @return the datatype for the given path.
	 */
	public DataType getDataType(DataTypePath dataTypePath);

	/**
	* Returns the dataTypeId for the given dataType.  If the dataType is not
	* currently in the dataTypeManger, it will be added
	* 
	 * @param dt the data type
	 * @return the ID of the resolved type
	*/
	public long getResolvedID(DataType dt);

	/**
	 * Returns the dataTypeId for the given dataType.  If the dataType does not exist,
	 * a -1 will be returned
	 * 
	 * @param dt the datatype to get an id for
	 * @return the ID of the type
	 */
	public long getID(DataType dt);

	/**
	 * Returns the dataType associated with the given dataTypeId or null if the dataTypeId is
	 * not valid
	 * 
	 * @param dataTypeID the ID
	 * @return the type
	 */
	public DataType getDataType(long dataTypeID);

	/**
	 * Returns the Category with the given id
	 * 
	 * @param categoryID id of the desired category
	 * @return the category
	 */
	public Category getCategory(long categoryID);

	/**
	 * Get the category that has the given path
	 * 
	 * @param path the path
	 * @return the category if defined, otherwise null
	 */
	public Category getCategory(CategoryPath path);

	/**
	 * Notification when data type is changed.
	 * @param dataType data type that is changed
	 * @param isAutoChange true if change was an automatic change in response to
	 * another datatype's change (e.g., size, alignment).
	 */
	public void dataTypeChanged(DataType dataType, boolean isAutoChange);

	/**
	 * Add a listener that is notified when the dataTypeManger changes.
	 * @param l the listener
	 */
	public void addDataTypeManagerListener(DataTypeManagerChangeListener l);

	/**
	 * Remove the DataTypeManger change listener.
	 * @param l the listener
	 */
	public void removeDataTypeManagerListener(DataTypeManagerChangeListener l);

	/**
	 * Adds a listener that will be notified when this manager's cache is invalidated.  This will
	 * happen when the system has changed and the manager cannot determine the exact change, like
	 * during an undo or a redo.
	 * @param listener The listener to add
	 */
	public void addInvalidatedListener(InvalidatedListener listener);

	/**
	 * Removes a previously added InvalidatedListener
	 * @param listener the listener to remove.
	 */
	public void removeInvalidatedListener(InvalidatedListener listener);

	/**
	 * Remove the given datatype from this manager
	 * @param dataType the dataType to be removed
	 * @param monitor the task monitor
	 * @return true if the data type existed and was removed
	 */
	public boolean remove(DataType dataType, TaskMonitor monitor);

	/**
	 * Return true if the given dataType exists in this data type manager
	 * 
	 * @param dataType the type
	 * @return true if the type is in this manager
	 */
	public boolean contains(DataType dataType);

	/**
	 * Create a category for the given path; returns the current category if it already exits
	 * 
	 * @param path the path
	 * @return the category
	 */
	public Category createCategory(CategoryPath path);

	/**
	 * Gets the data type with the indicated name in the indicated category.
	 * @param path the path for the category
	 * @param name the data type's name
	 * @return the data type.
	 */
	public DataType getDataType(CategoryPath path, String name);

	/**
	 * Returns this data type manager's name
	 * @return the name
	 */
	public String getName();

	/**
	 * Sets this data type manager's name
	 * @param name the new name
	 * @throws InvalidNameException if the given name is invalid (such as when null or empty)
	 */
	public void setName(String name) throws InvalidNameException;

	/**
	 * Starts a transaction for making changes in this data type manager.
	 * @param description a short description of the changes to be made.
	 * @return the transaction ID
	 */
	public int startTransaction(String description);

	/**
	 * Returns true if this DataTypeManager can be modified.
	 * @return true if this DataTypeMangaer can be modified.
	 */
	public boolean isUpdatable();

	/**
	 * Ends the current transaction
	 * @param transactionID id of the transaction to end
	 * @param commit true if changes are committed, false if changes in transaction are revoked
	 */
	public void endTransaction(int transactionID, boolean commit);

	/**
	 * Force all pending notification events to be flushed
	 * @throws IllegalStateException if the client is holding this object's lock
	 */
	public void flushEvents();

	/**
	 * Closes this dataType manager
	 */
	public void close();

	/**
	 * Returns a default sized pointer to the given datatype.  The pointer size is established
	 * dynamically based upon the data organization established by the compiler specification.
	 * 
	 * @param datatype the pointed to data type
	 * @return the pointer
	 */
	public Pointer getPointer(DataType datatype);

	/**
	 * Returns a pointer of the given size to the given datatype.
	 * Note: It is preferred to use default sized pointers when possible (i.e., size=-1,
	 * see {@link #getPointer(DataType)}) instead of explicitly specifying the size value.
	 * 
	 * @param datatype the pointed to data type
	 * @param size the size of the pointer to be created or -1 for a default sized pointer
	 * @return the pointer
	 */
	public Pointer getPointer(DataType datatype, int size);

	/**
	 * Returns the root category Manager
	 * @return the category
	 */
	public Category getRootCategory();

	/**
	 * Returns true if the given datatype has been designated as a favorite. If the datatype
	 * does not belong to this datatype manager, then false will be returned.
	 * @param datatype the datatype to check.
	 * @return true if the given datatype is a favorite in this manager.
	 */
	public boolean isFavorite(DataType datatype);

	/**
	 * Sets the given dataType to be either a favorite or not a favorite.
	 * @param datatype the datatype for which to change its status as a favorite.
	 * @param isFavorite true if the datatype is to be a favorite or false otherwise.
	 * @throws IllegalArgumentException if the given datatype does not belong to this manager.
	 */
	public void setFavorite(DataType datatype, boolean isFavorite);

	/**
	 * Returns a list of datatypes that have been designated as favorites.
	 * @return the list of favorite datatypes in this manager.
	 */
	public List<DataType> getFavorites();

	/**
	 * Returns the total number of data type categories
	 * @return the count
	 */
	public int getCategoryCount();

	/**
	 * Returns the total number of defined data types.
	 * @param includePointersAndArrays if true all pointers and array data types will be included
	 * @return the count
	 */
	public int getDataTypeCount(boolean includePointersAndArrays);

	/**
	 * Adds all enum value names that match the given value, to the given set.
	 * @param value the value to look for enum name matches
	 * @param enumValueNames the set to add matches to.
	 */
	public void findEnumValueNames(long value, Set<String> enumValueNames);

	public DataType getDataType(SourceArchive sourceArchive, UniversalID datatypeID);

	/**
	 * Get's the data type with the matching universal data type id.
	 * @param datatypeID The universal id of the data type to search for
	 * @return The data type with the matching UUID, or null if no such data type can be found.
	 */
	public DataType findDataTypeForID(UniversalID datatypeID);

	/**
	 * Returns the timestamp of the last time this manager was changed
	 * @return the timestamp
	 */
	public long getLastChangeTimeForMyManager();

	/**
	 * Returns the source archive for the given ID
	 * 
	 * @param sourceID the ID
	 * @return the archive; null if the ID is null; null if the archive does not exist
	 */
	public SourceArchive getSourceArchive(UniversalID sourceID);

	/**
	 * Returns this manager's archive type
	 * @return the type
	 */
	public ArchiveType getType();

	/**
	 * Returns all data types within this manager that have as their source the given archive
	 * 
	 * @param sourceArchive the archive
	 * @return the types
	 */
	public List<DataType> getDataTypes(SourceArchive sourceArchive);

	/**
	 * Returns the source archive for this manager
	 * @return the archive; null if the ID is null; null if the archive does not exist
	 */
	public SourceArchive getLocalSourceArchive();

	/**
	 * Change the given data type so that its source archive is the given archive
	 * 
	 * @param datatype the type
	 * @param archive the archive
	 */
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive);

	/**
	 * If the indicated data type is associated with a source archive, this will remove the
	 * association and the data type will become local to this data type manager.
	 * @param datatype the data type to be disassociated from a source archive.
	 */
	public void disassociate(DataType datatype);

	/**
	 * Updates the name associated with a source archive in this data type manager.
	 * @param archiveFileID Universal domain file ID of the source data type archive that has a new name.
	 * @param name the new name of the program or archive.
	 * @return true if the name associated with the source data type archive was changed.
	 * false if it wasn't changed.
	 */
	public boolean updateSourceArchiveName(String archiveFileID, String name);

	/**
	 * Updates the name associated with a source archive in this data type manager.
	 * @param sourceID Universal archive ID of the source data type archive that has a new name.
	 * @param name the new name of the program or archive.
	 * @return true if the name associated with the source data type archive was changed.
	 * false if it wasn't changed.
	 */
	public boolean updateSourceArchiveName(UniversalID sourceID, String name);

	/**
	 * Get the data organization associated with this data type manager.  Note that the
	 * DataOrganization settings may not be changed dynamically.
	 * @return data organization (will never be null)
	 */
	public DataOrganization getDataOrganization();

	/**
	 * Returns a list of source archives not including the builtin or the program's archive.
	 * @return a list of source archives not including the builtin or the program's archive.
	 */
	public List<SourceArchive> getSourceArchives();

	/**
	 * Removes the source archive from this manager.  This will disassociate all data types in
	 * this manager from the given archive.
	 * 
	 * @param sourceArchive the archive
	 */
	public void removeSourceArchive(SourceArchive sourceArchive);

	/**
	 * Returns or creates a persisted version of the given source archive
	 * @param sourceArchive the archive
	 * @return the archive
	 */
	public SourceArchive resolveSourceArchive(SourceArchive sourceArchive);

	/**
	 * Returns the data types within this data type manager that contain the specified data type.
	 * @param dataType the data type
	 * @return a set of data types that contain the specified data type.
	 */
	public Set<DataType> getDataTypesContaining(DataType dataType);
}
