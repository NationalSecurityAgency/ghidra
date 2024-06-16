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
package ghidra.program.util;

import static ghidra.program.util.ProgramEvent.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.util.FunctionChangeRecord.FunctionChangeType;

/**
 * ProgramEventerface to define event types and the method to generate an
 * event within Program.
 * <P>
 * Note: Previously (before 11.1), program change event types were defined in this file as
 * integer constants. Event ids have since been converted to enum types. The defines in this file  
 * have been converted to point to the new enum values to make it easier to convert to this new way  
 * and to clearly see how the old values map to the new enums. In future releases, these defines 
 * will be removed.
 */
public interface ChangeManager {

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param eventType the event type
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	public void setChanged(ProgramEvent eventType, Object oldValue, Object newValue);

	/**
	 * Notifies that register values have changed over the indicated address range.
	 * @param register register value which was modified (a value of null indicates all
	 * registers affected or unknown)
	 * @param start the start address for the range where values changed
	 * @param end the end address (inclusive) for the range where values changed
	 */
	public void setRegisterValuesChanged(Register register, Address start, Address end);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param eventType the event type
	 * @param start starting address that is affected by the event
	 * @param end ending address that is affected by the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	public void setChanged(ProgramEvent eventType, Address start, Address end, Object oldValue,
			Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param eventType the event type
	 * @param affected object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	public void setObjChanged(ProgramEvent eventType, Object affected, Object oldValue,
			Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param eventType the event type
	 * @param addr program address affected
	 * @param affected object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	public void setObjChanged(ProgramEvent eventType, Address addr, Object affected,
			Object oldValue, Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the DOCR_CODE_UNIT_PROPERTY_CHANGED event.
	 * @param propertyName name of property for the range that changed
	 * @param codeUnitAddr address of the code unit with the property change
	 * @param oldValue old value for the property
	 * @param newValue new value for the property
	 */
	public void setPropertyChanged(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue);

	/**
	 * Mark the state of the Program as having changed and generate
	 * the DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED event.
	 * @param propertyName name of property for the range being removed
	 * @param start start address of the range
	 * @param end end address of the range
	 */
	public void setPropertyRangeRemoved(String propertyName, Address start, Address end);

	////////////////////////////////////////////////////////////////////////////
	//
	//                           Deprecated event ids
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A memory block was created.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BLOCK_ADDED = MEMORY_BLOCK_ADDED;

	/**
	 * A memory block was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BLOCK_REMOVED = MEMORY_BLOCK_REMOVED;

	/**
	 * A memory block was changed. 
	 * (for example: its name, comment, or read, write, or execute flags were changed.)
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BLOCK_CHANGED = MEMORY_BLOCK_CHANGED;

	/**
	 * A block of memory was moved to a new start address.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BLOCK_MOVED = MEMORY_BLOCK_MOVED;

	/**
	 * A memory block was split ProgramEvento two memory blocks.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BLOCK_SPLIT = MEMORY_BLOCK_SPLIT;

	/**
	 * Two memory blocks were joined ProgramEvento a single memory block.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BLOCKS_JOINED = MEMORY_BLOCKS_JOINED;

	/**
	 * The bytes changed in memory.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEMORY_BYTES_CHANGED = MEMORY_BYTES_CHANGED;

	/**
	 * The memory image base has changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_IMAGE_BASE_CHANGED = IMAGE_BASE_CHANGED;

	/**
	 * A CodeUnit was added.  The "New Value" may be null when a block
	 * of Instructions are added
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_ADDED = CODE_ADDED;

	/**
	 * A CodeUnit was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_REMOVED = CODE_REMOVED;

	/**
	 * CodeUnits were moved from one Fragment to another.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_MOVED = FRAGMENT_CHANGED;

	/**
	 * Structure was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_COMPOSITE_ADDED = COMPOSITE_ADDED;

	/**
	 * Structure was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_COMPOSITE_REMOVED = COMPOSITE_REMOVED;

	/**
	 * Data was replaced.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_REPLACED = CODE_REPLACED;

	/**
	 * A property on a code unit was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_UNIT_PROPERTY_CHANGED = CODE_UNIT_PROPERTY_CHANGED;

	/**
	 * Generated whenever an entire user property manager is deleted.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED =
		CODE_UNIT_PROPERTY_ALL_REMOVED;

	/**
	 * Property over a range of addresses was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED =
		CODE_UNIT_PROPERTY_RANGE_REMOVED;

	/**
	 * A symbol was created.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_ADDED = SYMBOL_ADDED;

	/**
	 * A symbol was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_REMOVED = SYMBOL_REMOVED;

	/**
	 * The source of a symbol name was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_SOURCE_CHANGED = SYMBOL_SOURCE_CHANGED;

	/**
	 * The anchor flag for the symbol was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_ANCHORED_FLAG_CHANGED = SYMBOL_ANCHOR_FLAG_CHANGED;

	/**
	 * A symbol was set as primary.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_SET_AS_PRIMARY = SYMBOL_PRIMARY_STATE_CHANGED;

	/**
	 * A symbol was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_RENAMED = SYMBOL_RENAMED;

	/**
	 * An external entry poProgramEvent was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EXTERNAL_ENTRY_POINT_ADDED = EXTERNAL_ENTRY_ADDED;

	/**
	 * An external entry poProgramEvent was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EXTERNAL_ENTRY_POINT_REMOVED = EXTERNAL_ENTRY_REMOVED;

	/**
	 * The scope on a symbol changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_SCOPE_CHANGED = SYMBOL_SCOPE_CHANGED;

	/**
	 * An association to a symbol for a reference was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_ASSOCIATION_ADDED = SYMBOL_ASSOCIATION_ADDED;

	/**
	 * An association to a symbol for a reference was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_ASSOCIATION_REMOVED = SYMBOL_ASSOCIATION_REMOVED;

	/**
	 * Symbol data changed.  This corresponds to various
	 * changes within the symbol (e.g., primary status, datatype, external path or VariableStorage).
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_DATA_CHANGED = SYMBOL_DATA_CHANGED;

	/**
	 * Symbol address changed.  
	 * NOTE: This is only permitted for variable/parameter symbols
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SYMBOL_ADDRESS_CHANGED = SYMBOL_ADDRESS_CHANGED;

	/**
	 * A reference was added to a symbol.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEM_REFERENCE_ADDED = REFERENCE_ADDED;

	/**
	 * A reference was removed from a symbol.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEM_REFERENCE_REMOVED = REFERENCE_REMOVED;

	/**
	 * The ref type on a memory reference changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEM_REF_TYPE_CHANGED = REFERENCE_TYPE_CHANGED;

	/**
	 * The reference was identified as the primary.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEM_REF_PRIMARY_SET = REFERNCE_PRIMARY_SET;

	/**
	 * The primary reference was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MEM_REF_PRIMARY_REMOVED = REFERENCE_PRIMARY_REMOVED;

	/**
	 * The external path name changed for an external program name.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EXTERNAL_PATH_CHANGED = EXTERNAL_PATH_CHANGED;

	/**
	 * An external program name was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EXTERNAL_NAME_ADDED = EXTERNAL_NAME_ADDED;

	/**
	 * An external program name was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EXTERNAL_NAME_REMOVED = EXTERNAL_NAME_REMOVED;

	/**
	 * The name for an external program changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EXTERNAL_NAME_CHANGED = EXTERNAL_NAME_CHANGED;

	/**
	 * An Equate was created.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EQUATE_ADDED = EQUATE_ADDED;

	/**
	 * An Equate was deleted.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EQUATE_REMOVED = EQUATE_REMOVED;

	/**
	 * A reference at an operand was added to an Equate.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EQUATE_REFERENCE_ADDED = EQUATE_REFERENCE_ADDED;

	/**
	 * A reference at an operand was removed from an Equate.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EQUATE_REFERENCE_REMOVED = EQUATE_REFERENCE_REMOVED;

	/**
	 * An Equate was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EQUATE_RENAMED = EQUATE_RENAMED;

	/**
	 * A Module or Fragment was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_GROUP_ADDED = GROUP_ADDED;

	/**
	 * A Module or Fragment was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_GROUP_REMOVED = GROUP_REMOVED;

	/**
	 * A Module or Fragment was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_GROUP_RENAMED = GROUP_RENAMED;

	/**
	 * The comment for a Module or Fragment changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_GROUP_COMMENT_CHANGED = GROUP_COMMENT_CHANGED;

	/**
	 * The alias for a Module or Fragment changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_GROUP_ALIAS_CHANGED = GROUP_ALIAS_CHANGED;

	/**
	 * The children of a Module have been reordered.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_MODULE_REORDERED = MODULE_REORDERED;

	/**
	 * Fragment or set of fragments have been moved.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_FRAGMENT_MOVED = FRAGMENT_MOVED;

	/**
	 * Group was reparented.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_GROUP_REPARENTED = GROUP_REPARENTED;

	/**
	 * The end-of-line comment changed for a CodeUnit.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_EOL_COMMENT_CHANGED = COMMENT_CHANGED;

	/**
	 * The pre comment changed for a CodeUnit.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_PRE_COMMENT_CHANGED = COMMENT_CHANGED;

	/**
	 * The post comment changed for a CodeUnit.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_POST_COMMENT_CHANGED = COMMENT_CHANGED;

	/**
	 * A Plate comment was added, deleted, or changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_PLATE_COMMENT_CHANGED = COMMENT_CHANGED;

	/**
	 * A Repeatable Comment changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_REPEATABLE_COMMENT_CHANGED = COMMENT_CHANGED;

	/**
	 * Category was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_ADDED = DATA_TYPE_CATEGORY_ADDED;

	/**
	 * Category was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_REMOVED = DATA_TYPE_CATEGORY_REMOVED;

	/**
	 * Category was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_RENAMED = DATA_TYPE_CATEGORY_RENAMED;

	/**
	 * Category was moved.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_MOVED = DATA_TYPE_CATEGORY_MOVED;

	/**
	 * Data type was added to a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_ADDED = DATA_TYPE_ADDED;

	/**
	 * Data type was removed from a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_REMOVED = DATA_TYPE_REMOVED;

	/**
	 * Data Type was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_RENAMED = DATA_TYPE_RENAMED;

	/**
	 * Data type was moved to another category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_MOVED = DATA_TYPE_MOVED;

	/**
	 * Data type was updated.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_CHANGED = DATA_TYPE_CHANGED;

	/**
	 * The settings on a data type were updated.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_SETTING_CHANGED = DATA_TYPE_SETTING_CHANGED;

	/**
	 * Data type was replaced in a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_REPLACED = DATA_TYPE_REPLACED;

	/**
	 * Data type was added to a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SOURCE_ARCHIVE_ADDED = SOURCE_ARCHIVE_ADDED;

	/**
	 * Data type was updated.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_SOURCE_ARCHIVE_CHANGED = SOURCE_ARCHIVE_CHANGED;

	/**
	 * Bookmark type was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_BOOKMARK_TYPE_ADDED = BOOKMARK_TYPE_ADDED;

	/**
	 * Bookmark type was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_BOOKMARK_TYPE_REMOVED = BOOKMARK_TYPE_REMOVED;

	/**
	 * Bookmark was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_BOOKMARK_ADDED = BOOKMARK_ADDED;

	/**
	 * Bookmark was deleted.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_BOOKMARK_REMOVED = BOOKMARK_REMOVED;

	/**
	 * Bookmark category or comment was changed (old value not provided).
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_BOOKMARK_CHANGED = BOOKMARK_CHANGED;

	/**
	 * The language for the Program changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_LANGUAGE_CHANGED = LANGUAGE_CHANGED;

	/**
	 * Register values changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_REGISTER_VALUES_CHANGED = REGISTER_VALUES_CHANGED;

	/**
	 * An overlay address space was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_OVERLAY_SPACE_ADDED = OVERLAY_SPACE_ADDED;

	/**
	 * An overlay address space was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_OVERLAY_SPACE_REMOVED = OVERLAY_SPACE_REMOVED;

	/**
	 * An overlay address space was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_OVERLAY_SPACE_RENAMED = OVERLAY_SPACE_RENAMED;

	/**
	 * Tree was created.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_TREE_CREATED = PROGRAM_TREE_CREATED;

	/**
	 * Tree was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_TREE_REMOVED = PROGRAM_TREE_REMOVED;

	/**
	 * Tree was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_TREE_RENAMED = PROGRAM_TREE_RENAMED;

	/**
	 * A function tag was edited
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_TAG_CHANGED = FUNCTION_TAG_CHANGED;

	/**
	 * A function tag was created
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_TAG_CREATED = FUNCTION_TAG_CREATED;

	/**
	 * A function tag was created
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_TAG_DELETED = FUNCTION_TAG_DELETED;

	/**
	 * Function was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_ADDED = FUNCTION_TAG_APPLIED;

	/**
	 * Function was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_REMOVED = FUNCTION_TAG_UNAPPLIED;

	/**
	 * Function was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_CHANGED = FUNCTION_CHANGED;

	/**
	 * A function variable reference was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_VARIABLE_REFERENCE_ADDED = VARIABLE_REFERENCE_ADDED;

	/**
	 * A function variable reference was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_VARIABLE_REFERENCE_REMOVED = VARIABLE_REFERENCE_REMOVED;

	/**
	 * A function's body changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FUNCTION_BODY_CHANGED = FUNCTION_BODY_CHANGED;

	/**
	 * A function's purge size was changed. 
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_PURGE =
		FunctionChangeRecord.FunctionChangeType.PURGE_CHANGED;

	/**
	 * A function's inline state was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_INLINE =
		FunctionChangeRecord.FunctionChangeType.INLINE_CHANGED;

	/**
	 * A function's no-return state was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_NORETURN =
		FunctionChangeRecord.FunctionChangeType.NO_RETURN_CHANGED;

	/**
	 * A function's call-fixup state was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_CALL_FIXUP =
		FunctionChangeRecord.FunctionChangeType.CALL_FIXUP_CHANGED;

	/**
	 * A functions return type/storage was modified
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_RETURN =
		FunctionChangeRecord.FunctionChangeType.RETURN_TYPE_CHANGED;

	/**
	 * A functions parameter list was modified
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_PARAMETERS =
		FunctionChangeRecord.FunctionChangeType.PARAMETERS_CHANGED;

	/**
	 * A functions thunk status has changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static FunctionChangeType FUNCTION_CHANGED_THUNK =
		FunctionChangeRecord.FunctionChangeType.THUNK_CHANGED;

	/**
	 * An external reference was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_EXTERNAL_REFERENCE_ADDED = EXTERNAL_REFERENCE_ADDED;

	/**
	 * An external reference was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_EXTERNAL_REFERENCE_REMOVED = EXTERNAL_REFERENCE_REMOVED;

	/**
	 * A Fallthrough address was changed for an instruction.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FALLTHROUGH_CHANGED = FALLTHROUGH_CHANGED;

	/**
	 * The flow override for an instruction has changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_FLOWOVERRIDE_CHANGED = FLOW_OVERRIDE_CHANGED;

	/**
	 * An instruction length override was changed for an instruction.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_LENGTH_OVERRIDE_CHANGED = LENGTH_OVERRIDE_CHANGED;

	/**
	 * An AddressSetPropertyMap was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED =
		ADDRESS_PROPERTY_MAP_ADDED;

	/**
	 * An AddressSetPropertyMap was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED =
		ADDRESS_PROPERTY_MAP_REMOVED;

	/**
	 * An AddressSetPropertyMap was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED =
		ADDRESS_PROPERTY_MAP_CHANGED;

	/**
	 * An ProgramEventAddressSetPropertyMap was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED =
		INT_PROPERTY_MAP_ADDED;
	/**
	 * An ProgramEventAddressSetPropertyMap was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED =
		INT_PROPERTY_MAP_REMOVED;

	/**
	 * An ProgramEventAddressSetPropertyMap was changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static ProgramEvent DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED =
		INT_PROPERTY_MAP_CHANGED;

	/**
	 * User Data for a code unit changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CODE_UNIT_USER_DATA_CHANGED = CODE_UNIT_USER_DATA_CHANGED;

	/**
	 * User Data changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_USER_DATA_CHANGED = USER_DATA_CHANGED;

}
