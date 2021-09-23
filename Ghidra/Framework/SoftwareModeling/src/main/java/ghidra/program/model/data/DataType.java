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
 * The interface that all datatypes must implement.
 */
public interface DataType {

	/**
	 * WARNING: do not add <code>default</code> method implementations to this interface. Doing so
	 * intereferes with correct initialization of the static instance variables {@link #DEFAULT} and
	 * {@link #VOID} below.
	 */

	/**
	 * Singleton instance of default datatype.
	 */
	public static final DataType DEFAULT = DefaultDataType.dataType;

	/**
	 * Instance of void datatype (never use <code>==</code>)
	 * 
	 * @deprecated should use {@link VoidDataType#dataType} instead
	 */
	@Deprecated
	public static final DataType VOID = VoidDataType.dataType;

	public final static String CONFLICT_SUFFIX = ".conflict";

	static final long NO_SOURCE_SYNC_TIME = 0L;
	static final long NO_LAST_CHANGE_TIME = 0L;

	/**
	 * Indicates if the length of this data-type is determined based upon the
	 * {@link DataOrganization} obtained from the associated {@link DataTypeManager}.
	 * 
	 * @return true length is language/compiler-specification dependent, else false
	 */
	public boolean hasLanguageDependantLength();

	/**
	 * Gets a list of all the settingsDefinitions used by this datatype.
	 * 
	 * @return a list of the settingsDefinitions used by this datatype.
	 */
	public SettingsDefinition[] getSettingsDefinitions();

	/**
	 * Gets the default settings for this datatype.
	 * 
	 * @return the default settings for this datatype.
	 */
	public Settings getDefaultSettings();

	/**
	 * Returns an instance of this DataType with its universalID and SourceArchive identity
	 * retained.
	 * <p>
	 * The current instanceof will be returned if this datatype's DataTypeManager matches the
	 * specified dtm. The recursion depth of a clone will stop on any datatype whose DataTypeManager
	 * matches the specified dtm and simply use the existing datatype instance.
	 * 
	 * @param dtm the data-type manager instance whose data-organization should apply.
	 * @return cloned instance which may be the same as this instance
	 */
	public DataType clone(DataTypeManager dtm);

	/**
	 * Returns a new instance (shallow copy) of this DataType with a new identity.
	 * <p>
	 * Any reference to other datatypes will use {@link #clone(DataTypeManager)}.
	 * 
	 * @param dtm the data-type manager instance whose data-organization should apply.
	 * @return new instanceof of this datatype
	 */
	public DataType copy(DataTypeManager dtm);

	/**
	 * Gets the categoryPath associated with this datatype
	 * 
	 * @return the datatype's category path
	 */
	public CategoryPath getCategoryPath();

	/**
	 * Returns the dataTypePath for this datatype;
	 * 
	 * @return the dataTypePath for this datatype;
	 */
	public DataTypePath getDataTypePath();

	/**
	 * Set the categoryPath associated with this datatype
	 * 
	 * @param path the new path
	 * @throws DuplicateNameException if an attempt to place this datatype into the specified
	 *             category resulted in a name collision. This should not occur for non-DB DataType
	 *             instances.
	 */
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException;

	/**
	 * Get the DataTypeManager containing this datatype.
	 * <p>
	 * This association should not be used to indicate whether this DataType has been resolved, but
	 * is intended to indicate whether the appropriate DataOrganization is being used.
	 * 
	 * @return the DataTypeManager that is associated with this datatype.
	 */
	public DataTypeManager getDataTypeManager();

	/**
	 * Gets the name for referring to this datatype.
	 * 
	 * @return generic name for this Data Type (i.e.: Word)
	 */
	public String getDisplayName();

	/**
	 * Get the name of this datatype.
	 * 
	 * @return the name
	 */
	public String getName();

	/**
	 * Get the full category path name that includes this datatype's name.
	 * <p>
	 * If the category is null, then this just the datatype's name is returned.
	 * 
	 * @return the path, or just this type's name
	 */
	public String getPathName();

	/**
	 * Sets the name of the datatype
	 * 
	 * @param name the new name for this datatype.
	 * @throws InvalidNameException if the given name does not form a valid name.
	 * @throws DuplicateNameException if name change on stored {@link DataType} is a duplicate of
	 *             another datatype within the same category (only applies to DB stored
	 *             {@link DataType}).
	 */
	public void setName(String name) throws InvalidNameException, DuplicateNameException;

	/**
	 * Sets the name and category of a datatype at the same time.
	 * 
	 * @param path the new category path.
	 * @param name the new name
	 * @throws InvalidNameException if the name is invalid
	 * @throws DuplicateNameException if name change on stored {@link DataType} is a duplicate of
	 *             another datatype within the same category (only applies to DB stored
	 *             {@link DataType}).
	 */
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException;

	/**
	 * Get the mnemonic for this DataType.
	 * 
	 * @param settings settings which may influence the result or null
	 * @return the mnemonic for this DataType.
	 */
	public String getMnemonic(Settings settings);

	/**
	 * Get the length (number of 8-bit bytes) of this DataType.
	 * <p>
	 * NOTE: No datatype should ever return 0, even if {@link #isZeroLength()}, and only
	 * {@link Dynamic} datatypes should return -1. If {@link #isZeroLength()} is true a length of 1
	 * should be returned. Where a zero-length datatype can be handled (e.g., {@link Composite}) the
	 * {@link #isZeroLength()} method should be used.
	 * 
	 * @return the length of this DataType
	 */
	public int getLength();

	/**
	 * Indicates this datatype is defined with a zero length.
	 * <p>
	 * This method should not be confused with {@link #isNotYetDefined()} which indicates that
	 * nothing but the name and basic type is known.
	 * <p>
	 * NOTE: a zero-length datatype must return a length of 1 via {@link #getLength()}. Zero-length
	 * datatypes used as a component within a {@link Composite} may, or may not, be assigned a
	 * component length of 0. The method {@link DataTypeComponent#usesZeroLengthComponent(DataType)}
	 * is used to make this determination.
	 * 
	 * @return true if type definition has a length of 0, else false
	 */
	public boolean isZeroLength();

	/**
	 * Indicates if this datatype has not yet been fully defined.
	 * <p>
	 * Such datatypes should always return a {@link #getLength()} of 1 and true for
	 * {@link #isZeroLength()}. (example: empty structure)
	 * 
	 * @return true if this type is not yet defined.
	 */
	public boolean isNotYetDefined();

	/**
	 * Get a String briefly describing this DataType.
	 *
	 * @return a one-liner describing this DataType.
	 */
	public String getDescription();

	/**
	 * Sets a String briefly describing this DataType.
	 * 
	 * @param description a one-liner describing this DataType.
	 * @throws UnsupportedOperationException if the description is not allowed to be set for this
	 *             datatype.
	 */
	public void setDescription(String description) throws UnsupportedOperationException;

	/**
	 * The getDocs method should provide a URL pointing to extended documentation for this DataType
	 * if it exists.
	 * <p>
	 * A typical use would be to return a URL pointing to the programmers reference for this
	 * instruction or a page describing this data structure.
	 *
	 * @return null - there is no URL documentation for this prototype.
	 */
	public URL getDocs();

	/**
	 * Get the data in the form of the appropriate Object for this DataType.
	 * <p>
	 * For instance if the datatype is an AddressDT, return an Address object. a Byte, return a
	 * Scalar* (maybe this should be a Byte) a Float, return a Float
	 *
	 * @param buf the data buffer.
	 * @param settings the settings to use.
	 * @param length the number of bytes to get the value from.
	 * @return the data Object.
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length);

	/**
	 * Check if this type supports encoding (patching)
	 * <p>
	 * If unsupported, {@link #encodeValue(Object, MemBuffer, Settings, int)} and
	 * {@link #encodeRepresentation(String, MemBuffer, Settings, int)} will always throw an
	 * exception. Actions which rely on either {@code encode} method should not be displayed if the
	 * applicable datatype is not encodable.
	 * 
	 * @return true if encoding is supported
	 */
	public boolean isEncodable();

	/**
	 * Encode bytes from an Object appropriate for this DataType.
	 * <p>
	 * Converts the given object to the byte encoding and returns it. When appropriate, this should
	 * seek the nearest encoding to the specified value, since the object may come from a user
	 * script. For example, a floating-point value may be rounded. Invalid values should be rejected
	 * with a {@link DataTypeEncodeException}.
	 * 
	 * @param value the desired value.
	 * @param buf a buffer representing the eventual destination of the bytes.
	 * @param settings the settings to use.
	 * @param length the expected length of the result, usually the length of the data unit, or -1
	 *            to let the type choose the length. It may be ignored, e.g., for fixed-length
	 *            types.
	 * @return the encoded value.
	 * @throws DataTypeEncodeException if the value cannot be encoded for any reason, e.g.,
	 *             incorrect type, not enough space, buffer overflow, unsupported (see
	 *             {@link #isEncodable()}).
	 */
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException;

	/**
	 * Get the Class of the value to be returned by this datatype.
	 * 
	 * @param settings the relevant settings to use or null for default.
	 * @return Class of the value to be returned by this datatype or null if it can vary or is
	 *         unspecified. Types which correspond to a string or char array will return the String
	 *         class.
	 */
	public Class<?> getValueClass(Settings settings);

	/**
	 * Returns the appropriate string to use as the default label prefix in the absence of any data.
	 * 
	 * @return the default label prefix or null if none specified.
	 */
	public String getDefaultLabelPrefix();

	/**
	 * Returns the prefix to use for this datatype when an abbreviated prefix is desired.
	 * <p>
	 * For example, some datatypes will built a large default label, at which is is more desirable
	 * to have a shortened prefix.
	 *
	 * @return the prefix to use for this datatype when an abbreviated prefix is desired. May return
	 *         null.
	 */
	public String getDefaultAbbreviatedLabelPrefix();

	/**
	 * Returns the appropriate string to use as the default label prefix.
	 * 
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param len the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @return the default label prefix or null if none specified.
	 */
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options);

	/**
	 * Returns the appropriate string to use as the default label prefix.
	 * <p>
	 * This takes into account the fact that there exists a reference to the data that references
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
	 * Encode bytes according to the display format for this type.
	 * <p>
	 * Converts the given representation to the byte encoding and returns it. When appropriate, this
	 * should seek the nearest encoding to the specified value, since the representation is likely
	 * coming from user input. For example, a floating-point value may be rounded. Invalid
	 * representations should be rejected with a {@link DataTypeEncodeException}.
	 * 
	 * @param repr the representation of the desired value, as in
	 *            {@link #getRepresentation(MemBuffer, Settings, int)}. The supported formats depend
	 *            on the specific datatype and its settings.
	 * @param buf a buffer representing the eventual destination of the bytes.
	 * @param settings the settings to use for the representation.
	 * @param length the expected length of the result, usually the length of the data unit, or -1
	 *            to let the type choose the length. It may be ignored, e.g., for fixed-length
	 *            types.
	 * @return the encoded value.
	 * @throws DataTypeEncodeException if the value cannot be encoded for any reason, e.g.,
	 *             incorrect format, not enough space, buffer overflow, unsupported (see
	 *             {@link #isEncodable()}).
	 */
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException;

	/**
	 * Returns true if this datatype has been deleted and is no longer valid
	 * 
	 * @return true if this datatype has been deleted and is no longer valid.
	 */
	public boolean isDeleted();

	/**
	 * Check if the given datatype is equivalent to this datatype.
	 * <p>
	 * The precise meaning of "equivalent" is datatype dependent. <br>
	 * NOTE: if invoked by a DB object or manager it should be invoked on the DataTypeDB object
	 * passing the other datatype as the argument.
	 * 
	 * @param dt the datatype being tested for equivalence.
	 * @return true if the if the given datatype is equivalent to this datatype.
	 */
	public boolean isEquivalent(DataType dt);

	/**
	 * Notification that the given datatype's size has changed.
	 * <p>
	 * DataTypes may need to make internal changes in response. <br>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param dt the datatype that has changed.
	 */
	public void dataTypeSizeChanged(DataType dt);

	/**
	 * Notification that the given datatype's alignment has changed.
	 * <p>
	 * DataTypes may need to make internal changes in response. <br>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param dt the datatype that has changed.
	 */
	public void dataTypeAlignmentChanged(DataType dt);

	/**
	 * Informs this datatype that the given datatype has been deleted.
	 * <p>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param dt the datatype that has been deleted.
	 */
	public void dataTypeDeleted(DataType dt);

	/**
	 * Informs this datatype that the given oldDT has been replaced with newDT
	 * <p>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param oldDt old datatype
	 * @param newDt new datatype
	 */
	public void dataTypeReplaced(DataType oldDt, DataType newDt);

	/**
	 * Set the default settings for this datatype.
	 * <p>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param settings the settings to be used as this dataTypes default settings.
	 */
	public void setDefaultSettings(Settings settings);

	/**
	 * Inform this datatype that it has the given parent
	 * <p>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param dt parent datatype
	 */
	public void addParent(DataType dt);

	/**
	 * Remove a parent datatype
	 * <p>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param dt parent datatype
	 */
	public void removeParent(DataType dt);

	/**
	 * Informs this datatype that its name has changed from the indicated old name.
	 * <p>
	 * TODO: This method is reserved for internal DB use. <br>
	 * 
	 * @param dt the datatype whose name changed
	 * @param oldName the datatype's old name
	 */
	public void dataTypeNameChanged(DataType dt, String oldName);

	/**
	 * Get the parents of this datatype
	 * 
	 * @return an array of parents of this datatype
	 */
	public DataType[] getParents();

	/**
	 * Gets the alignment to be used when aligning this datatype within another datatype.
	 * 
	 * @return this datatype's alignment.
	 */
	public int getAlignment();

	/**
	 * Check if this datatype depends on the existence of the given datatype.
	 * <p>
	 * For example byte[] depends on byte. If byte were deleted, then byte[] would also be deleted.
	 * 
	 * @param dt the datatype to test that this datatype depends on.
	 * @return true if the existence of this datatype relies on the existence of the specified
	 *         datatype dt.
	 */
	public boolean dependsOn(DataType dt);

	/**
	 * Get the source archive where this type originated
	 * 
	 * @return source archive object
	 */
	public SourceArchive getSourceArchive();

	/**
	 * Set the source archive where this type originated
	 * 
	 * @param archive source archive object
	 */
	public void setSourceArchive(SourceArchive archive);

	/**
	 * Get the timestamp corresponding to the last time this type was changed within its datatype
	 * manager
	 * 
	 * @return timestamp of last change within datatype manager
	 */
	public long getLastChangeTime();

	/**
	 * Get the timestamp corresponding to the last time this type was sync'd within its source
	 * archive
	 * 
	 * @return timestamp of last sync with source archive
	 */
	public long getLastChangeTimeInSourceArchive();

	/**
	 * Get the universal ID for this datatype.
	 * <p>
	 * This value is intended to be a unique identifier across all programs and archives. The same
	 * ID indicates that two datatypes were originally the same one. Keep in mind names, categories,
	 * and component makeup may differ and have changed since there origin.
	 * 
	 * @return datatype UniversalID
	 */
	public UniversalID getUniversalID();

	/**
	 * For datatypes that support change, this method replaces the internals of this datatype with
	 * the internals of the given datatype.
	 * <p>
	 * The datatypes must be of the same "type" (i.e. structure can only be replacedWith another
	 * structure.
	 * 
	 * @param datatype the datatype that contains the internals to upgrade to.
	 * @throws UnsupportedOperationException if the datatype does not support change.
	 * @throws IllegalArgumentException if the given datatype is not the same type as this datatype.
	 */
	public void replaceWith(DataType dataType);

	/**
	 * Sets the lastChangeTime for this datatype.
	 * <p>
	 * Normally, this is updated automatically when a datatype is changed, but when committing or
	 * updating while synchronizing an archive, the lastChangeTime may need to be updated
	 * externally.
	 * 
	 * @param lastChangeTime the time to use as the lastChangeTime for this datatype
	 */
	public void setLastChangeTime(long lastChangeTime);

	/**
	 * Sets the lastChangeTimeInSourceArchive for this datatype.
	 * <p>
	 * This is used by when a datatype change is committed back to its source archive.
	 * 
	 * @param lastChangeTimeInSourceArchive the time to use as the lastChangeTimeInSourceArchive for
	 *            this datatype
	 */
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive);

	/**
	 * Returns the DataOrganization associated with this data-type
	 * 
	 * @return associated data organization
	 */
	public DataOrganization getDataOrganization();

}
