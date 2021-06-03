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

import java.net.URL;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * The interface that all data types must implement.
 */
public interface DataType {

	public static final DataType DEFAULT = DefaultDataType.dataType; // global default data type
	public static final DataType VOID = VoidDataType.dataType; // global void data type

	public final static String CONFLICT_SUFFIX = ".conflict";

	static final long NO_SOURCE_SYNC_TIME = 0L;
	static final long NO_LAST_CHANGE_TIME = 0L;

	/**
	 * Indicates if the length of this data-type is determined based
	 * upon the {@link DataOrganization} obtained from the associated {@link DataTypeManager}.
	 * @return true length is language/compiler-specification dependent, else false
	 */
	public boolean hasLanguageDependantLength();

	/**
	 * Indicates if type has not yet been defined.
	 * Such types will always return a size of 1.
	 * (example: empty structure)
	 * @return true if this type is not yet defined.
	 */
	public boolean isNotYetDefined();

	/**
	 * Gets a list of all the settingsDefinitions used by this data type.
	 * @return a list of the settingsDefinitions used by this data type.
	 */
	public SettingsDefinition[] getSettingsDefinitions();

	/**
	 * Gets the default settings for this data type.
	 * @return the default settings for this dataType.
	 */
	public Settings getDefaultSettings();

	/**
	 * Returns an instance of this DataType with its universalID and SourceArchive identity retained.
	 * The current instanceof will be returned if this datatype's DataTypeManager matches 
	 * the specified dtm. The recursion depth of a clone will stop on any datatype whose
	 * DataTypeManager matches the specified dtm and simply use the existing datatype instance.
	 * @param dtm the data-type manager instance whose data-organization should apply.
	 * @return cloned instance which may be the same as this instance
	 */
	public DataType clone(DataTypeManager dtm);

	/**
	 * Returns a new instance (shallow copy) of this DataType with a new identity. 
	 * Any reference to other datatypes will use {@link #clone(DataTypeManager)}.
	 * @param dtm the data-type manager instance whose data-organization should apply.
	 * @return new instanceof of this datatype
	 */
	public DataType copy(DataTypeManager dtm);

	/**
	 * Gets the categoryPath associated with this data type
	 * @return the datatype's category path
	 */
	public CategoryPath getCategoryPath();

	/** 
	 * Returns the dataTypePath for this dataType;
	 * @return the dataTypePath for this dataType;
	 */
	public DataTypePath getDataTypePath();

	/**
	 * @param path set the categoryPath associated with this data type
	 * @throws DuplicateNameException if an attempt to place this datatype into the 
	 * specified category resulted in a name collision.  This should not occur for non-DB 
	 * DataType instances.
	 */
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException;

	/**
	 * @return the DataTypeManager that is associated with this dataType.
	 * This association should not be used to indicate whether this DataType has been 
	 * resolved, but is intended to indicate whether the appropriate DataOrganization
	 * is being used.
	 */
	public DataTypeManager getDataTypeManager();

	/**
	 * Gets the name for referring to this data type.
	 * @return generic name for this Data Type (i.e.: Word)
	 */
	public String getDisplayName();

	/**
	 * @return the name of this data type
	 */
	public String getName();

	/**
	 * @return the full category path name that includes this dataType's name.  If
	 * the category is null, then this just the dataType's name is returned.
	 */
	public String getPathName();

	/**
	 * Sets the name of the dataType
	 * @param name the new name for this dataType.
	 * @throws InvalidNameException if the given name does not form a valid name.
	 * @throws DuplicateNameException if name change on stored {@link DataType}
	 * is a duplicate of another datatype within the same category (only applies to 
	 * DB stored {@link DataType}).
	 */
	public void setName(String name) throws InvalidNameException, DuplicateNameException;

	/**
	 * Sets the name and category of a dataType at the same time.  
	 * @param path the new category path.
	 * @param name the new name
	 * @throws InvalidNameException if the name is invalid
	 * @throws DuplicateNameException if name change on stored {@link DataType}
	 * is a duplicate of another datatype within the same category (only applies to 
	 * DB stored {@link DataType}).
	 */
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException;

	/**
	 * Get the mnemonic for this DataType.
	 * @param settings settings which may influence the result or null
	 * @return the mnemonic for this DataType.
	 */
	public String getMnemonic(Settings settings);

	/**
	 * Get the length (number of 8-bit bytes) of this DataType.
	 * @return the length of this DataType
	 */
	public int getLength();

	/**
	 * Indicates is this datatype is defined with a zero length.
	 * This method should not be confused with {@link #isNotYetDefined()}
	 * which indicates that nothing but the name and basic type is known.
	 * NOTE: Support for zero-length datatypes is not yet fully supported, as a result
	 * they will generally return a non-zero length.
	 * @return true if type definition has a length of 0 even though it may report
	 * a length of 1, else false.  
	 */
	public boolean isZeroLength();

	/**
	 * Get a String briefly describing this DataType.
	 *
	 * @return a one-liner describing this DataType.
	 */
	public String getDescription();

	/**
	 * Sets a String briefly describing this DataType.
	 * @param description a one-liner describing this DataType.
	 * @throws UnsupportedOperationException if the description is not allowed to be set for this data type.
	 */
	public void setDescription(String description) throws UnsupportedOperationException;

	/**
	 * The getDocs method should provide a URL pointing to extended
	 * documentation for this DataType if it exists. A typical
	 * use would be to return a URL pointing to the programmers
	 * reference for this instruction or a page describing this
	 * data structure.
	 *
	 * @return null - there is no URL documentation for this prototype.
	 */
	public URL getDocs();

	/**
	 * Get the data in the form of the appropriate Object for
	 * this DataType.
	 *
	 * For instance if the data type is an AddressDT, return an Address object.
	 *                                  a Byte, return a Scalar* (maybe this should be a Byte)
	 *                                  a Float, return a Float
	 *
	 * @param buf the data buffer.
	 * @param settings the settings to use.
	 * @param length the number of bytes to get the value from.
	 * @return the data Object.
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length);

	/**
	 * Get the Class of the value to be returned by this data type.
	 * @param settings the relevant settings to use or null for default.
	 * @return Class of the value to be returned by this data type or null if it can vary
	 * or is unspecified.  Types which correspond to a string or char array will
	 * return the String class.
	 */
	public Class<?> getValueClass(Settings settings);

	/**
	 * Returns the appropriate string to use as the default label prefix in the absence of any data.
	 * @return the default label prefix or null if none specified.
	 */
	public String getDefaultLabelPrefix();

	/**
	 * Returns the prefix to use for this datatype when an abbreviated prefix is desired.  For
	 * example, some data types will built a large default label, at which is is more desirable to
	 * have a shortened prefix.
	 *
	 * @return the prefix to use for this datatype when an abbreviated prefix is desired.  May
	 *         return null.
	 */
	public String getDefaultAbbreviatedLabelPrefix();

	/**
	 * Returns the appropriate string to use as the default label prefix.
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param len the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @return the default label prefix or null if none specified.
	 */
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options);

	/**
	 * Returns the appropriate string to use as the default label prefix, taking into account 
	 * the fact that there exists a reference to the data that references
	 * <code>offcutLength</code> bytes into this type 
	 * 
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param len the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @param offcutOffset offset into datatype
	 * @return the default label prefix.
	 */
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutOffset);

	/**
	 * Get bytes from memory in a printable format for this type.
	 *
	 * @param buf the data.
	 * @param settings the settings to use for the representation.
	 * @param length the number of bytes to represent.
	 * @return the representation of the data in this format, never null.
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length);

	/** 
	 * Returns true if this data type has been deleted and is no longer valid
	 * @return true if this data type has been deleted and is no longer valid.
	 */
	public boolean isDeleted();

	/**
	 * Returns true if the given dataType is equivalent to this dataType.  The
	 * precise meaning of "equivalent" is dataType dependent.
	 * <br>
	 * NOTE: if invoked by a DB object or manager it should be invoked on the
	 * DataTypeDB object passing the other datatype as the argument.
	 * @param dt the dataType being tested for equivalence.
	 * @return true if the if the given dataType is equivalent to this dataType.
	 */
	public boolean isEquivalent(DataType dt);

	/**
	 * Notification that the given dataType's size has changed.  DataTypes may
	 * need to make internal changes in response.
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param dt the dataType that has changed.
	 */
	public void dataTypeSizeChanged(DataType dt);

	/**
	 * Notification that the given dataType's alignment has changed.  DataTypes may
	 * need to make internal changes in response.
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param dt the dataType that has changed.
	 */
	public void dataTypeAlignmentChanged(DataType dt);

	/**
	 * Informs this dataType that the given dataType has been deleted.
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param dt the dataType that has been deleted.
	 */
	public void dataTypeDeleted(DataType dt);

	/**
	 * Informs this data type that the given oldDT has been replaced with newDT
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param oldDt old data type
	 * @param newDt new data type
	 */
	public void dataTypeReplaced(DataType oldDt, DataType newDt);

	/**
	 * Set the default settings for this data type.
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param settings the settings to be used as this dataTypes default settings. 
	 */
	public void setDefaultSettings(Settings settings);

	/**
	 * Inform this data type that it has the given parent
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param dt parent data type
	 */
	public void addParent(DataType dt);

	/**
	 * Remove a parent data type
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param dt parent data type
	 */
	public void removeParent(DataType dt);

	/**
	 * Informs this data type that its name has changed from the indicated old name.
	 * <br>
	 * TODO: This method is reserved for internal DB use.
	 * <br>
	 * @param dt the data type whose name changed
	 * @param oldName the data type's old name
	 */
	public void dataTypeNameChanged(DataType dt, String oldName);

	/**
	 * @return an array of parents of this data type
	 */
	public DataType[] getParents();

	/**
	 * Gets the alignment to be used when aligning this data type within another data type.
	 * @return this data type's alignment.
	 */
	public int getAlignment();

	/**
	 * Returns true if this dataType depends on the existence of the given dataType.
	 * For example byte[] depends on byte.  If byte were deleted, then byte[] would
	 * also be deleted.
	 * @param dt the dataType to test that this dataType depends on.
	 * @return true if the existence of this datatype relies on the existence
	 * of the specified datatype dt.
	 */
	public boolean dependsOn(DataType dt);

	/**
	 * Get the source archive where this type originated
	 * @return source archive object
	 */
	public SourceArchive getSourceArchive();

	/**
	 * Set the source archive where this type originated
	 * @param archive source archive object
	 */
	public void setSourceArchive(SourceArchive archive);

	/**
	 * Get the timestamp corresponding to the last time this type was changed
	 * within its data type manager
	 * @return timestamp of last change within data type manager
	 */
	public long getLastChangeTime();

	/**
	 * Get the timestamp corresponding to the last time this type was sync'd
	 * within its source archive
	 * @return timestamp of last sync with source archive
	 */
	public long getLastChangeTimeInSourceArchive();

	/**
	 * Get the universal ID for this data type.  This value is intended to be a
	 * unique identifier across all programs and archives.  The same ID indicates 
	 * that two data types were originally the same one.  Keep in mind names, categories,
	 * and component makeup may differ and have changed since there origin.
	 * @return data type UniversalID
	 */
	public UniversalID getUniversalID();

	/**
	 * For dataTypes that support change, this method replaces the internals of this dataType with
	 * the internals of the given dataType.  The dataTypes must be of the same "type" (i.e. structure
	 * can only be replacedWith  another structure.
	 * @param dataType the dataType that contains the internals to upgrade to.
	 * @throws UnsupportedOperationException if the dataType does not support change.
	 * @throws IllegalArgumentException if the given dataType is not the same type as this dataType.
	 */
	public void replaceWith(DataType dataType);

	/**
	 * Sets the lastChangeTime for this dataType.  Normally, this is updated automatically when
	 * a dataType is changed, but when committing or updating while synchronizing an archive, the 
	 * lastChangeTime may need to be updated externally.
	 * @param lastChangeTime the time to use as the lastChangeTime for this dataType
	 */
	public void setLastChangeTime(long lastChangeTime);

	/**
	 * Sets the lastChangeTimeInSourceArchive for this dataType. This is used by when a dataType
	 * change is committed back to its source archive.
	 * @param lastChangeTimeInSourceArchive the time to use as the lastChangeTimeInSourceArchive for this dataType
	 */
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive);

	/**
	 * Returns the DataOrganization associated with this data-type
	 */
	public DataOrganization getDataOrganization();

}
