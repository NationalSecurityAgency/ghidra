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
package ghidra.app.util.bin.format.dwarf;

import java.util.*;

import ghidra.program.model.symbol.SymbolType;

/**
 * Identifier/purpose of a DWARF DIE record.
 * <p>
 * Users of this enum should be tolerant of unknown tag id values.  See 
 * {@link DWARFAbbreviation}'s tagId.
 */
public enum DWARFTag {
	DW_TAG_array_type(0x1),
	DW_TAG_class_type(0x2),
	DW_TAG_entry_point(0x3),
	DW_TAG_enumeration_type(0x4),
	DW_TAG_formal_parameter(0x5),
	DW_TAG_imported_declaration(0x8),
	DW_TAG_label(0xa),
	DW_TAG_lexical_block(0xb),
	DW_TAG_member(0xd),
	DW_TAG_pointer_type(0xf),
	DW_TAG_reference_type(0x10),
	DW_TAG_compile_unit(0x11),
	DW_TAG_string_type(0x12),
	DW_TAG_structure_type(0x13),
	DW_TAG_subroutine_type(0x15),
	DW_TAG_typedef(0x16),
	DW_TAG_union_type(0x17),
	DW_TAG_unspecified_parameters(0x18),
	DW_TAG_variant(0x19),
	DW_TAG_common_block(0x1a),
	DW_TAG_common_inclusion(0x1b),
	DW_TAG_inheritance(0x1c),
	DW_TAG_inlined_subroutine(0x1d),
	DW_TAG_module(0x1e),
	DW_TAG_ptr_to_member_type(0x1f),
	DW_TAG_set_type(0x20),
	DW_TAG_subrange_type(0x21),
	DW_TAG_with_stmt(0x22),
	DW_TAG_access_declaration(0x23),
	DW_TAG_base_type(0x24),
	DW_TAG_catch_block(0x25),
	DW_TAG_const_type(0x26),
	DW_TAG_constant(0x27),
	DW_TAG_enumerator(0x28),
	DW_TAG_file_type(0x29),
	DW_TAG_friend(0x2a),
	DW_TAG_namelist(0x2b),
	DW_TAG_namelist_item(0x2c),
	DW_TAG_packed_type(0x2d),
	DW_TAG_subprogram(0x2e),
	DW_TAG_template_type_param(0x2f),
	DW_TAG_template_value_param(0x30),
	DW_TAG_thrown_type(0x31),
	DW_TAG_try_block(0x32),
	DW_TAG_variant_part(0x33),
	DW_TAG_variable(0x34),
	DW_TAG_volatile_type(0x35),
	DW_TAG_dwarf_procedure(0x36),
	DW_TAG_restrict_type(0x37),
	DW_TAG_interface_type(0x38),
	DW_TAG_namespace(0x39),
	DW_TAG_imported_module(0x3a),
	DW_TAG_unspecified_type(0x3b),
	DW_TAG_partial_unit(0x3c),
	DW_TAG_imported_unit(0x3d),
	DW_TAG_mutable_type(0x3e),
	DW_TAG_condition(0x3f),
	DW_TAG_shared_type(0x40),
	DW_TAG_type_unit(0x41),
	DW_TAG_rvalue_reference_type(0x42),
	DW_TAG_template_alias(0x43),
	DW_TAG_coarray_type(0x44),
	DW_TAG_generic_subrange(0x45),
	DW_TAG_dynamic_type(0x46),
	DW_TAG_atomic_type(0x47),
	DW_TAG_call_site(0x48),
	DW_TAG_call_site_parameter(0x49),
	DW_TAG_skeleton_unit(0x4a),
	DW_TAG_immutable_type(0x4b),

	DW_TAG_lo_user(0x4080),
	
	DW_TAG_MIPS_loop(0x4081),
	DW_TAG_HP_array_descriptor(0x4090),
	DW_TAG_HP_Bliss_field(0x4091),
	DW_TAG_HP_Bliss_field_set(0x4092),
	
	DW_TAG_format_label(0x4101), // original comment mentions FORTRAN
	DW_TAG_function_template(0x4102),
	DW_TAG_class_template(0x4103),
	DW_TAG_GNU_BINCL(0x4104),
	DW_TAG_GNU_EINCL(0x4105),
	DW_TAG_GNU_template_template_param(0x4106),
	DW_TAG_GNU_template_parameter_pack(0x4107),
	DW_TAG_GNU_formal_parameter_pack(0x4108),
	DW_TAG_gnu_call_site(0x4109),
	DW_TAG_gnu_call_site_parameter(0x410a),

	DW_TAG_APPLE_ptrauth_type(0x4300),  // Apple proprietary
	
	DW_TAG_hi_user(0xffff),
	
	
	DW_TAG_UNKNOWN(-1); // fake ghidra tag

	
	
	private int id;

	DWARFTag(int id) {
		this.id = id;
	}

	/**
	 * Returns the name of this enum, falling back to the rawTagId value if this enum is the
	 * DW_TAG_UNKNOWN value.
	 * 
	 * @param rawTagId tag id that corresponds to actual tag id found in the DWARF data 
	 * @return string name of this enum
	 */
	public String name(int rawTagId) {
		return this != DW_TAG_UNKNOWN
				? name()
				: "DW_TAG_??? %d (0x%x)".formatted(rawTagId, rawTagId);
	}

	public int getId() {
		return id;
	}

	public boolean isType() {
		return TYPE_TAGS.contains(this);
	}

	public boolean isNamedType() {
		switch (this) {
			case DW_TAG_base_type:
			case DW_TAG_typedef:
			case DW_TAG_namespace:
			case DW_TAG_subprogram:
			case DW_TAG_class_type:
			case DW_TAG_interface_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			case DW_TAG_enumeration_type:
			case DW_TAG_subroutine_type:
			case DW_TAG_unspecified_type:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Returns true if the children of this DIE are within a new namespace.
	 * <p>
	 * Ie. Namespaces, subprogram, class, interface, struct, union, enum
	 * 
	 * @return true if the children of this DIE are within a new namespace
	 */
	public boolean isNameSpaceContainer() {
		switch (this) {
			case DW_TAG_namespace:
			case DW_TAG_subprogram:
			case DW_TAG_lexical_block:
			case DW_TAG_class_type:
			case DW_TAG_interface_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			case DW_TAG_enumeration_type:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Returns true if this DIE defines a structure-like element (class, struct, interface, union).
	 *
	 * @return true if this DIE defines a structure-like element (class, struct, interface, union)
	 */
	public boolean isStructureType() {
		switch (this) {
			case DW_TAG_class_type:
			case DW_TAG_interface_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
				return true;
			default:
				return false;
		}
	}

	public boolean isFuncDefType() {
		switch (this) {
			case DW_TAG_subprogram:
			case DW_TAG_subroutine_type:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Returns a string that describes what kind of object is specified by the {@link DIEAggregate}.
	 * <p>
	 * Used to create a name for anonymous types.
	 *
	 * @return String describing the type of the DIEA.
	 */
	public String getContainerTypeName() {
		switch (this) {
			case DW_TAG_structure_type:
				return "struct";
			case DW_TAG_class_type:
				return "class";
			case DW_TAG_enumeration_type:
				return "enum";
			case DW_TAG_union_type:
				return "union";
			case DW_TAG_lexical_block:
				return "lexical_block";
			case DW_TAG_subprogram:
				return "subprogram";
			case DW_TAG_subroutine_type:
				return "subr";
			case DW_TAG_variable:
				return "var";
			default:
				return "unknown";
		}
	}

	/**
	 * Returns the {@link SymbolType} that corresponds to a DWARF tag
	 * <p>
	 * The mapping between tag type and SymbolType is not exact.  There is no matching
	 * SymbolType for a DWARF static variable, so "LOCAL_VAR" is used currently.
	 * <p>
	 * This mainly is used in constructing a NamespacePath, and the only critical usage
	 * there is Namespace vs. Class vs. everything else.
	 *
	 * @return {@link SymbolType}
	 */
	public SymbolType getSymbolType() {
		switch (this) {

			case DW_TAG_subprogram:
				return SymbolType.FUNCTION;

			case DW_TAG_structure_type:
			case DW_TAG_interface_type:
			case DW_TAG_class_type:
			case DW_TAG_union_type:
			case DW_TAG_enumeration_type:
				return SymbolType.CLASS;

			case DW_TAG_namespace:
				return SymbolType.NAMESPACE;
			case DW_TAG_formal_parameter:
				return SymbolType.PARAMETER;

			case DW_TAG_variable:
				return SymbolType.LOCAL_VAR;

			case DW_TAG_base_type:
			case DW_TAG_typedef:
			default:
				return null;

		}
	}

	//---------------------------------------------------------------------------------------------

	public static DWARFTag of(int tagId) {
		return lookupMap.getOrDefault(tagId, DW_TAG_UNKNOWN);
	}

	private static Map<Integer, DWARFTag> lookupMap = buildLookup();

	private static Map<Integer, DWARFTag> buildLookup() {
		Map<Integer, DWARFTag> result = new HashMap<>();
		for (DWARFTag tag : values()) {
			if (result.put(tag.id, tag) != null) {
				throw new RuntimeException("Duplicate DWARFTag enum const value " + tag);
			}
		}
		return result;
	}

	private static final Set<DWARFTag> TYPE_TAGS = EnumSet.of(DW_TAG_base_type, DW_TAG_array_type,
		DW_TAG_typedef, DW_TAG_class_type, DW_TAG_interface_type, DW_TAG_structure_type,
		DW_TAG_union_type, DW_TAG_enumeration_type, DW_TAG_pointer_type, DW_TAG_reference_type,
		DW_TAG_rvalue_reference_type, DW_TAG_const_type, DW_TAG_volatile_type,
		DW_TAG_ptr_to_member_type, DW_TAG_unspecified_type, DW_TAG_subroutine_type);

}
