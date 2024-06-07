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

import ghidra.framework.model.DomainObjectEventIdGenerator;
import ghidra.framework.model.EventType;
import ghidra.program.model.listing.Program;

/**
 * Event types for {@link Program} changes.
 */
public enum ProgramEvent implements EventType {
	MEMORY_BLOCK_ADDED,					// memory block added
	MEMORY_BLOCK_REMOVED,				// memory block removed
	MEMORY_BLOCK_CHANGED,				// memory block property changed
	MEMORY_BLOCK_MOVED,					// memory block start address changed 
	MEMORY_BLOCK_SPLIT,					// memory block split into two blocks
	MEMORY_BLOCKS_JOINED,				// memory blocks joined into one block
	MEMORY_BYTES_CHANGED,				// memory bytes changed

	IMAGE_BASE_CHANGED,					// image base changed

	CODE_ADDED,							// instructions or data set at an address
	CODE_REMOVED,						// instructions or data cleared at an address
	CODE_REPLACED,						// the instruction or data type at an address was changed

	COMPOSITE_ADDED,					// a non-primitive data type was added
	COMPOSITE_REMOVED,					// a non-primitive data type was removed

	CODE_UNIT_PROPERTY_CHANGED,			// a property map value changed
	CODE_UNIT_PROPERTY_ALL_REMOVED,		// a property map was removed
	CODE_UNIT_PROPERTY_RANGE_REMOVED,	// a ranges of values was removed

	SYMBOL_ADDED,						// a symbol was added
	SYMBOL_REMOVED,						// a symbol was removed
	SYMBOL_SOURCE_CHANGED,				// a symbol's source was changed
	SYMBOL_ANCHOR_FLAG_CHANGED,			// a symbol's pinned status was changed
	SYMBOL_PRIMARY_STATE_CHANGED,		// a symbol primary status changed
	SYMBOL_RENAMED,						// a symbol was renamed
	SYMBOL_SCOPE_CHANGED,				// the set of addresses associated with a symbol changed
	SYMBOL_ASSOCIATION_ADDED,			// a symbol association was added to a reference
	SYMBOL_ASSOCIATION_REMOVED,			// a symbol association was removed from a reference
	SYMBOL_DATA_CHANGED,				// some symbol property was changed 
	SYMBOL_ADDRESS_CHANGED,				// the symbol's address changed (only applies to param and variables)

	EXTERNAL_ENTRY_ADDED,				// an external entry point was added
	EXTERNAL_ENTRY_REMOVED,				// an external entry point was removed
	EXTERNAL_PATH_CHANGED,				// the external path name changed for an external program
	EXTERNAL_NAME_ADDED,				// an external program name was added
	EXTERNAL_NAME_REMOVED,				// an external program name was removed
	EXTERNAL_NAME_CHANGED,				// the name of an external program was changed
	EXTERNAL_REFERENCE_ADDED,			// an external reference was added
	EXTERNAL_REFERENCE_REMOVED,			// an external reference was removed

	REFERENCE_ADDED,					// a memory reference was added
	REFERENCE_REMOVED,					// a memory reference was removed
	REFERENCE_TYPE_CHANGED,				// a memory reference's type was changed
	REFERNCE_PRIMARY_SET,				// a memory reference was made to be primary
	REFERENCE_PRIMARY_REMOVED,			// a memory reference was made to be no longer primary

	EQUATE_ADDED,						// an equate was created
	EQUATE_REMOVED,						// an equate was deleted
	EQUATE_REFERENCE_ADDED,				// a reference to an equate was created
	EQUATE_REFERENCE_REMOVED,			// a reference to an equate was deleted
	EQUATE_RENAMED,						// an equate was renamed

	PROGRAM_TREE_CREATED,				// a new program tree was created
	PROGRAM_TREE_REMOVED,				// a program tree was deleted
	PROGRAM_TREE_RENAMED,
	GROUP_ADDED,						// a module or fragment was created in a program tree
	GROUP_REMOVED,						// a module or fragment was removed from a program tree
	GROUP_RENAMED,						// a module or fragment was renamed
	GROUP_COMMENT_CHANGED,				// the comment for a module or fragment was changed
	GROUP_ALIAS_CHANGED,				// the alias for a module or fragment was changed
	GROUP_REPARENTED,					// a module or fragment's parent changed
	MODULE_REORDERED,					// the children of a module changed order
	FRAGMENT_MOVED,						// a fragment was moved
	FRAGMENT_CHANGED,					// the addresses in a fragment were changed

	COMMENT_CHANGED,					// a comment was changed

	DATA_TYPE_CATEGORY_ADDED,			// a new data type category was created
	DATA_TYPE_CATEGORY_REMOVED,			// a data type category was deleted
	DATA_TYPE_CATEGORY_RENAMED,			// a data type category was renamed
	DATA_TYPE_CATEGORY_MOVED,			// a data type category was moved (reparented)
	DATA_TYPE_ADDED,					// a data type was created
	DATA_TYPE_REMOVED,					// a data type was deleted
	DATA_TYPE_RENAMED,					// a data type was renamed
	DATA_TYPE_MOVED,					// a data type was moved
	DATA_TYPE_CHANGED,					// a data type was changed
	DATA_TYPE_SETTING_CHANGED,			// a data type's settings changed (default or at specific address)
	DATA_TYPE_REPLACED,					// a data type was replaced
	SOURCE_ARCHIVE_ADDED,				// a new data type source archive was defined
	SOURCE_ARCHIVE_CHANGED,				// a data type source archive was changed

	BOOKMARK_TYPE_ADDED,				// a new bookmark type was defined
	BOOKMARK_TYPE_REMOVED,				// a bookmark type was deleted
	BOOKMARK_ADDED,						// a bookmark was added
	BOOKMARK_REMOVED,					// a bookmark was removed
	BOOKMARK_CHANGED,					// a bookmark was changed

	LANGUAGE_CHANGED,					// the program's language was changed
	REGISTER_VALUES_CHANGED,			// the value of a register changed over some address range
	OVERLAY_SPACE_ADDED,				// a new overlay address space was created
	OVERLAY_SPACE_REMOVED,				// an overlay address space was deleted
	OVERLAY_SPACE_RENAMED,				// an overlay address space was renamed

	FUNCTION_TAG_CREATED,				// a function tag was created
	FUNCTION_TAG_CHANGED,				// a function tag was changed
	FUNCTION_TAG_DELETED,				// a function tag was deleted
	FUNCTION_TAG_APPLIED,				// a function tag was applied to a function
	FUNCTION_TAG_UNAPPLIED,				// a function tag was removed from a function

	FUNCTION_ADDED,						// a function was created
	FUNCTION_REMOVED,					// a function was removed
	FUNCTION_BODY_CHANGED,				// a function's body (address set) changed
	FUNCTION_CHANGED,					// one of many function attributes changed. See FunctionSubEvents Enum

	VARIABLE_REFERENCE_ADDED,			// a function variable reference was added
	VARIABLE_REFERENCE_REMOVED,			// a function variable reference was removed

	FALLTHROUGH_CHANGED,				// a fallthrough address was changed for an instruction
	FLOW_OVERRIDE_CHANGED,				// the flow override was changed for an instruction
	LENGTH_OVERRIDE_CHANGED,			// the instruction length override was changed for an instruction

	ADDRESS_PROPERTY_MAP_ADDED,			// an address set property map was created
	ADDRESS_PROPERTY_MAP_REMOVED,		// an address set property map was deleted
	ADDRESS_PROPERTY_MAP_CHANGED,		// an address set property map was changed

	INT_PROPERTY_MAP_ADDED,				// an int property map was created
	INT_PROPERTY_MAP_REMOVED,			// an int property map was removed
	INT_PROPERTY_MAP_CHANGED,			// an int property map was changed

	CODE_UNIT_USER_DATA_CHANGED,		// user data has changed for some code unit
	USER_DATA_CHANGED,					// general user data has changed at some address

	RELOCATION_ADDED;					// a relocation entry was added

	private final int id = DomainObjectEventIdGenerator.next();

	@Override
	public int getId() {
		return id;
	}

}
