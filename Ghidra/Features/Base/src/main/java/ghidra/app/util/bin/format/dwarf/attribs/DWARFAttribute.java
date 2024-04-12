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
package ghidra.app.util.bin.format.dwarf.attribs;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeClass.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;

/**
 * Defines the names and numeric ids of known DWARF attributes.  Well-known attributes are also
 * constrained to certain value types (see {@link DWARFAttributeClass}).
 * <p>
 * Users of this enum should be tolerant of unknown attribute id values.  See 
 * {@link AttrDef#getRawAttributeId()}.
 */
public enum DWARFAttribute {
	DW_AT_sibling(0x1, reference),
	DW_AT_location(0x2, exprloc, loclist, block),
	DW_AT_name(0x3, string),
	DW_AT_ordering(0x9, constant),
	//DW_AT_subscr_data(0xa),
	DW_AT_byte_size(0xb, constant, exprloc, reference),
	DW_AT_bit_offset(0xc),	// dwarf-3
	DW_AT_bit_size(0xd, constant, exprloc, reference),
	//DW_AT_element_list(0xf),
	DW_AT_stmt_list(0x10, lineptr, constant),
	DW_AT_low_pc(0x11, address),
	DW_AT_high_pc(0x12, address, constant),
	DW_AT_language(0x13, constant),
	//DW_AT_member(0x14),
	DW_AT_discr(0x15, reference),
	DW_AT_discr_value(0x16, constant),
	DW_AT_visibility(0x17, constant),
	DW_AT_import(0x18, reference),
	DW_AT_string_length(0x19, exprloc, loclist, reference),
	DW_AT_common_reference(0x1a, reference),
	DW_AT_comp_dir(0x1b, string),
	DW_AT_const_value(0x1c, block, constant, string),
	DW_AT_containing_type(0x1d, reference),
	DW_AT_default_value(0x1e, constant, reference, flag),
	DW_AT_inline(0x20, constant),
	DW_AT_is_optional(0x21, flag),
	DW_AT_lower_bound(0x22, constant, exprloc, reference),
	DW_AT_producer(0x25, string),
	DW_AT_prototyped(0x27, flag),
	DW_AT_return_addr(0x2a, exprloc, loclist),
	DW_AT_start_scope(0x2c, constant, rnglist),
	DW_AT_bit_stride(0x2e, constant, exprloc, reference),
	DW_AT_upper_bound(0x2f, constant, exprloc, reference),
	DW_AT_abstract_origin(0x31, reference),
	DW_AT_accessibility(0x32, constant),
	DW_AT_address_class(0x33, constant),
	DW_AT_artificial(0x34, flag),
	DW_AT_base_types(0x35, reference),
	DW_AT_calling_convention(0x36, constant),
	DW_AT_count(0x37, constant, exprloc, reference),
	DW_AT_data_member_location(0x38, constant, exprloc, loclist),
	DW_AT_decl_column(0x39, constant),
	DW_AT_decl_file(0x3a, constant),
	DW_AT_decl_line(0x3b, constant),
	DW_AT_declaration(0x3c, flag),
	DW_AT_discr_list(0x3d, block),
	DW_AT_encoding(0x3e, constant),
	DW_AT_external(0x3f, flag),
	DW_AT_frame_base(0x40, exprloc, loclist, block),
	DW_AT_friend(0x41, reference),
	DW_AT_identifier_case(0x42, constant),
	DW_AT_macro_info(0x43, macptr),
	DW_AT_namelist_item(0x44, reference),
	DW_AT_priority(0x45, reference),
	DW_AT_segment(0x46, exprloc, loclist),
	DW_AT_specification(0x47, reference),
	DW_AT_static_link(0x48, exprloc, loclist),
	DW_AT_type(0x49, reference),
	DW_AT_use_location(0x4a, exprloc, loclist),
	DW_AT_variable_parameter(0x4b, flag),
	DW_AT_virtuality(0x4c, constant),
	DW_AT_vtable_elem_location(0x4d, exprloc, loclist),
	DW_AT_allocated(0x4e, constant, exprloc, reference),
	DW_AT_associated(0x4f, constant, exprloc, reference),
	DW_AT_data_location(0x50, exprloc),
	DW_AT_byte_stride(0x51, constant, exprloc, reference),
	DW_AT_entry_pc(0x52, address, constant),
	DW_AT_use_UTF8(0x53, flag),
	DW_AT_extension(0x54, reference),
	DW_AT_ranges(0x55, rnglist),
	DW_AT_trampoline(0x56, address, flag, reference, string),
	DW_AT_call_column(0x57, constant),
	DW_AT_call_file(0x58, constant),
	DW_AT_call_line(0x59, constant),
	DW_AT_description(0x5a, string),
	DW_AT_binary_scale(0x5b, constant),
	DW_AT_decimal_scale(0x5c, constant),
	DW_AT_small(0x5d, reference),
	DW_AT_decimal_sign(0x5e, constant),
	DW_AT_digit_count(0x5f, constant),
	DW_AT_picture_string(0x60, string),
	DW_AT_mutable(0x61, flag),
	DW_AT_threads_scaled(0x62, flag),
	DW_AT_explicit(0x63, flag),
	DW_AT_object_pointer(0x64, reference),
	DW_AT_endianity(0x65, constant),
	DW_AT_elemental(0x66, flag),
	DW_AT_pure(0x67, flag),
	DW_AT_recursive(0x68, flag),
	DW_AT_signature(0x69, reference),
	DW_AT_main_subprogram(0x6a, flag),
	DW_AT_data_bit_offset(0x6b, constant),
	DW_AT_const_expr(0x6c, flag),
	DW_AT_enum_class(0x6d, flag),
	DW_AT_linkage_name(0x6e, string),
	DW_AT_string_length_bit_size(0x6f, constant),
	DW_AT_string_length_byte_size(0x70, constant),
	DW_AT_rank(0x71, constant, exprloc),
	DW_AT_str_offsets_base(0x72, stroffsetsptr),
	DW_AT_addr_base(0x73, addrptr),
	DW_AT_rnglists_base(0x74, rnglistsptr),
	// 0x75 reserved, unused
	DW_AT_dwo_name(0x76, string),
	DW_AT_reference(0x77, flag),
	DW_AT_rvalue_reference(0x78, flag),
	DW_AT_macros(0x79, macptr),
	DW_AT_call_all_calls(0x7a, flag),
	DW_AT_call_all_source_calls(0x7b, flag),
	DW_AT_call_all_tail_calls(0x7c, flag),
	DW_AT_call_return_pc(0x7d, address),
	DW_AT_call_value(0x7e, exprloc),
	DW_AT_call_origin(0x7f, exprloc),
	DW_AT_call_parameter(0x80, reference),
	DW_AT_call_pc(0x81, address),
	DW_AT_call_tail_call(0x82, flag),
	DW_AT_call_target(0x83, exprloc),
	DW_AT_call_target_clobbered(0x84, exprloc),
	DW_AT_call_data_location(0x85, exprloc),
	DW_AT_call_data_value(0x86, exprloc),
	DW_AT_noreturn(0x87, flag),
	DW_AT_alignment(0x88, constant),
	DW_AT_export_symbols(0x89, flag),
	DW_AT_deleted(0x8a, flag),
	DW_AT_defaulted(0x8b, constant),
	DW_AT_loclists_base(0x8c, loclistsptr),

	DW_AT_lo_user(0x2000),
	DW_AT_hi_user(0x3fff),
	DW_AT_MIPS_linkage_name(0x2007),

	// GNU DebugFission stuff
	DW_AT_GNU_dwo_name(0x2130),
	DW_AT_GNU_dwo_id(0x2131),
	DW_AT_GNU_ranges_base(0x2132),
	DW_AT_GNU_addr_base(0x2133),
	DW_AT_GNU_pubnames(0x2134),
	DW_AT_GNU_pubtypes(0x2135),
	// end GNU DebugFission

	// Golang
	DW_AT_go_kind(0x2900),
	DW_AT_go_key(0x2901),
	DW_AT_go_elem(0x2902),
	DW_AT_go_embedded_field(0x2903),
	DW_AT_go_runtime_type(0x2904),
	DW_AT_go_package_name(0x2905),
	DW_AT_go_dict_index(0x2906),
	// end Golang

	// Apple proprietary tags
	DW_AT_APPLE_ptrauth_key(0x3e04),
	DW_AT_APPLE_ptrauth_address_discriminated(0x3e05),
	DW_AT_APPLE_ptrauth_extra_discriminator(0x3e06),
	DW_AT_APPLE_omit_frame_ptr(0x3fe7),
	DW_AT_APPLE_optimized(0x3fe1);
	// end Apple proprietary tags

	private int id;
	private Set<DWARFAttributeClass> attributeClass;

	DWARFAttribute(int id, DWARFAttributeClass... attributeClass) {
		this.id = id;
		this.attributeClass = EnumSet.noneOf(DWARFAttributeClass.class);
		this.attributeClass.addAll(List.of(attributeClass));
	}

	public int getId() {
		return id;
	}

	public Set<DWARFAttributeClass> getAttributeClass() {
		return attributeClass;
	}

	public static final int EOL = 0;	// value used as end of attributespec list

	public static DWARFAttribute of(int attributeInt) {
		return lookupMap.get(attributeInt);
	}

	private static Map<Integer, DWARFAttribute> lookupMap = buildLookup();

	private static Map<Integer, DWARFAttribute> buildLookup() {
		Map<Integer, DWARFAttribute> result = new HashMap<>();
		for (DWARFAttribute attr : values()) {
			result.put(attr.id, attr);
		}
		return result;
	}

	/**
	 * Represents how a specific DWARF attribute is stored in a DIE record.
	 */
	public static class AttrDef extends DWARFAttributeDef<DWARFAttribute> {

		/**
		 * Reads a {@link DWARFAttribute.AttrDef} instance from the {@link BinaryReader reader}.
		 * <p>
		 * Returns a null if its a end-of-list marker.
		 * <p>
		 * @param reader {@link BinaryReader} abbr stream
		 * @return new {@link AttrDef}, or null if end-of-list
		 * @throws IOException if error reading
		 */
		public static AttrDef read(BinaryReader reader) throws IOException {
			DWARFAttributeDef<DWARFAttribute> tmp =
				DWARFAttributeDef.read(reader, DWARFAttribute::of);
			if (tmp == null) {
				return null;
			}

			return new AttrDef(tmp.getAttributeId(), tmp.getRawAttributeId(),
				tmp.getAttributeForm(), tmp.getImplicitValue());
		}

		public AttrDef(DWARFAttribute attributeId, int rawAttributeId,
				DWARFForm attributeForm, long implicitValue) {
			super(attributeId, rawAttributeId, attributeForm, implicitValue);
		}

		@Override
		protected String getRawAttributeIdDescription() {
			return "DW_AT_???? %d (0x%x)".formatted(rawAttributeId, rawAttributeId);
		}

		@Override
		public AttrDef withForm(DWARFForm newForm) {
			return new AttrDef(attributeId, rawAttributeId, newForm, implicitValue);
		}

	}

}
