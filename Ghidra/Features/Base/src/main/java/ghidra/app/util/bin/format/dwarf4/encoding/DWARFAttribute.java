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
package ghidra.app.util.bin.format.dwarf4.encoding;

import ghidra.app.util.bin.format.dwarf4.DWARFUtil;

public final class DWARFAttribute {
	public static final int DW_AT_sibling = 0x1;
	public static final int DW_AT_location = 0x2;
	public static final int DW_AT_name = 0x3;
	public static final int DW_AT_ordering = 0x9;
	//public static final int DW_AT_subscr_data = 0xa;
	public static final int DW_AT_byte_size = 0xb;
	public static final int DW_AT_bit_offset = 0xc;
	public static final int DW_AT_bit_size = 0xd;
	//public static final int DW_AT_element_list = 0xf;
	public static final int DW_AT_stmt_list = 0x10;
	public static final int DW_AT_low_pc = 0x11;
	public static final int DW_AT_high_pc = 0x12;
	public static final int DW_AT_language = 0x13;
	//public static final int DW_AT_member = 0x14;
	public static final int DW_AT_discr = 0x15;
	public static final int DW_AT_discr_value = 0x16;
	public static final int DW_AT_visibility = 0x17;
	public static final int DW_AT_import = 0x18;
	public static final int DW_AT_string_length = 0x19;
	public static final int DW_AT_common_reference = 0x1a;
	public static final int DW_AT_comp_dir = 0x1b;
	public static final int DW_AT_const_value = 0x1c;
	public static final int DW_AT_containing_type = 0x1d;
	public static final int DW_AT_default_value = 0x1e;
	public static final int DW_AT_inline = 0x20;
	public static final int DW_AT_is_optional = 0x21;
	public static final int DW_AT_lower_bound = 0x22;
	public static final int DW_AT_producer = 0x25;
	public static final int DW_AT_prototyped = 0x27;
	public static final int DW_AT_return_addr = 0x2a;
	public static final int DW_AT_start_scope = 0x2c;
	public static final int DW_AT_bit_stride = 0x2e;
	public static final int DW_AT_upper_bound = 0x2f;
	public static final int DW_AT_abstract_origin = 0x31;
	public static final int DW_AT_accessibility = 0x32;
	public static final int DW_AT_address_class = 0x33;
	public static final int DW_AT_artificial = 0x34;
	public static final int DW_AT_base_types = 0x35;
	public static final int DW_AT_calling_convention = 0x36;
	public static final int DW_AT_count = 0x37;
	public static final int DW_AT_data_member_location = 0x38;
	public static final int DW_AT_decl_column = 0x39;
	public static final int DW_AT_decl_file = 0x3a;
	public static final int DW_AT_decl_line = 0x3b;
	public static final int DW_AT_declaration = 0x3c;
	public static final int DW_AT_discr_list = 0x3d;
	public static final int DW_AT_encoding = 0x3e;
	public static final int DW_AT_external = 0x3f;
	public static final int DW_AT_frame_base = 0x40;
	public static final int DW_AT_friend = 0x41;
	public static final int DW_AT_identifier_case = 0x42;
	public static final int DW_AT_macro_info = 0x43;
	public static final int DW_AT_namelist_item = 0x44;
	public static final int DW_AT_priority = 0x45;
	public static final int DW_AT_segment = 0x46;
	public static final int DW_AT_specification = 0x47;
	public static final int DW_AT_static_link = 0x48;
	public static final int DW_AT_type = 0x49;
	public static final int DW_AT_use_location = 0x4a;
	public static final int DW_AT_variable_parameter = 0x4b;
	public static final int DW_AT_virtuality = 0x4c;
	public static final int DW_AT_vtable_elem_location = 0x4d;
	public static final int DW_AT_allocated = 0x4e;
	public static final int DW_AT_associated = 0x4f;
	public static final int DW_AT_data_location = 0x50;
	public static final int DW_AT_byte_stride = 0x51;
	public static final int DW_AT_entry_pc = 0x52;
	public static final int DW_AT_use_UTF8 = 0x53;
	public static final int DW_AT_extension = 0x54;
	public static final int DW_AT_ranges = 0x55;
	public static final int DW_AT_trampoline = 0x56;
	public static final int DW_AT_call_column = 0x57;
	public static final int DW_AT_call_file = 0x58;
	public static final int DW_AT_call_line = 0x59;
	public static final int DW_AT_description = 0x5a;
	public static final int DW_AT_binary_scale = 0x5b;
	public static final int DW_AT_decimal_scale = 0x5c;
	public static final int DW_AT_small = 0x5d;
	public static final int DW_AT_decimal_sign = 0x5e;
	public static final int DW_AT_digit_count = 0x5f;
	public static final int DW_AT_picture_string = 0x60;
	public static final int DW_AT_mutable = 0x61;
	public static final int DW_AT_threads_scaled = 0x62;
	public static final int DW_AT_explicit = 0x63;
	public static final int DW_AT_object_pointer = 0x64;
	public static final int DW_AT_endianity = 0x65;
	public static final int DW_AT_elemental = 0x66;
	public static final int DW_AT_pure = 0x67;
	public static final int DW_AT_recursive = 0x68;
	public static final int DW_AT_signature = 0x69;
	public static final int DW_AT_main_subprogram = 0x6a;
	public static final int DW_AT_data_bit_offset = 0x6b;
	public static final int DW_AT_const_expr = 0x6c;
	public static final int DW_AT_enum_class = 0x6d;
	public static final int DW_AT_linkage_name = 0x6e;
	public static final int DW_AT_string_length_bit_size = 0x6f;
	public static final int DW_AT_string_length_byte_size = 0x70;
	public static final int DW_AT_rank = 0x71;
	public static final int DW_AT_str_offsets_base = 0x72;
	public static final int DW_AT_addr_base = 0x73;
	public static final int DW_AT_rnglists_base = 0x74;
	// 0x75 reserved, unused
	public static final int DW_AT_dwo_name = 0x76;
	public static final int DW_AT_reference = 0x77;
	public static final int DW_AT_rvalue_reference = 0x78;
	public static final int DW_AT_macros = 0x79;
	public static final int DW_AT_call_all_calls = 0x7a;
	public static final int DW_AT_call_all_source_calls = 0x7b;
	public static final int DW_AT_call_all_tail_calls = 0x7c;
	public static final int DW_AT_call_return_pc = 0x7d;
	public static final int DW_AT_call_value = 0x7e;
	public static final int DW_AT_call_origin = 0x7f;
	public static final int DW_AT_call_parameter = 0x80;
	public static final int DW_AT_call_pc = 0x81;
	public static final int DW_AT_call_tail_call = 0x82;
	public static final int DW_AT_call_target = 0x83;
	public static final int DW_AT_call_target_clobbered = 0x84;
	public static final int DW_AT_call_data_location = 0x85;
	public static final int DW_AT_call_data_value = 0x86;
	public static final int DW_AT_noreturn = 0x87;
	public static final int DW_AT_alignment = 0x88;
	public static final int DW_AT_export_symbols = 0x89;
	public static final int DW_AT_deleted = 0x8a;
	public static final int DW_AT_defaulted = 0x8b;
	public static final int DW_AT_loclists_base = 0x8c;

	public static final int DW_AT_lo_user = 0x2000;
	public static final int DW_AT_hi_user = 0x3fff;
	public static final int DW_AT_MIPS_linkage_name = 0x2007;

	// GNU DebugFission stuff
	public static final int DW_AT_GNU_dwo_name = 0x2130;
	public static final int DW_AT_GNU_dwo_id = 0x2131;
	public static final int DW_AT_GNU_ranges_base = 0x2132;
	public static final int DW_AT_GNU_addr_base = 0x2133;
	public static final int DW_AT_GNU_pubnames = 0x2134;
	public static final int DW_AT_GNU_pubtypes = 0x2135;
	// end GNU DebugFission

	public static String toString(long value) {
		return DWARFUtil.toString(DWARFAttribute.class, value);
	}
}
