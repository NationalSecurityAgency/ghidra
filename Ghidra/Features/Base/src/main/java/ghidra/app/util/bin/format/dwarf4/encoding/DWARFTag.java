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

/**
 * DWARF uses a series of debugging information entries to define a 
 * low-level representation of a source program. Each debugging 
 * information entry is described by an identifying tag and
 * contains a series of attributes. The tag specifies the class 
 * to which an entry belongs, and the attributes define the 
 * specific characteristics of the entry.
 * <p>
 * The debugging information entries in DWARF Version 2, 3, and 4 are 
 * intended to exist in the .debug_info section of an object file.
 * <p>
 * The set of required tag names is listed below.
 */
public final class DWARFTag
{
	public static final int DW_TAG_array_type = 0x1;
	public static final int DW_TAG_class_type = 0x2;
	public static final int DW_TAG_entry_point = 0x3;
	public static final int DW_TAG_enumeration_type = 0x4;
	public static final int DW_TAG_formal_parameter = 0x5;
	public static final int DW_TAG_imported_declaration = 0x8;
	public static final int DW_TAG_label = 0xa;
	public static final int DW_TAG_lexical_block = 0xb;
	public static final int DW_TAG_member = 0xd;
	public static final int DW_TAG_pointer_type = 0xf;
	public static final int DW_TAG_reference_type = 0x10;
	public static final int DW_TAG_compile_unit = 0x11;
	public static final int DW_TAG_string_type = 0x12;
	public static final int DW_TAG_structure_type = 0x13;
	public static final int DW_TAG_subroutine_type = 0x15;
	public static final int DW_TAG_typedef = 0x16;
	public static final int DW_TAG_union_type = 0x17;
	public static final int DW_TAG_unspecified_parameters = 0x18;
	public static final int DW_TAG_variant = 0x19;
	public static final int DW_TAG_common_block = 0x1a;
	public static final int DW_TAG_common_inclusion = 0x1b;
	public static final int DW_TAG_inheritance = 0x1c;
	public static final int DW_TAG_inlined_subroutine = 0x1d;
	public static final int DW_TAG_module = 0x1e;
	public static final int DW_TAG_ptr_to_member_type = 0x1f;
	public static final int DW_TAG_set_type = 0x20;
	public static final int DW_TAG_subrange_type = 0x21;
	public static final int DW_TAG_with_stmt = 0x22;
	public static final int DW_TAG_access_declaration = 0x23;
	public static final int DW_TAG_base_type = 0x24;
	public static final int DW_TAG_catch_block = 0x25;
	public static final int DW_TAG_const_type = 0x26;
	public static final int DW_TAG_constant = 0x27;
	public static final int DW_TAG_enumerator = 0x28;
	public static final int DW_TAG_file_type = 0x29;
	public static final int DW_TAG_friend = 0x2a;
	public static final int DW_TAG_namelist = 0x2b;
	public static final int DW_TAG_namelist_item = 0x2c;
	public static final int DW_TAG_packed_type = 0x2d;
	public static final int DW_TAG_subprogram = 0x2e;
	public static final int DW_TAG_template_type_param = 0x2f;
	public static final int DW_TAG_template_value_param = 0x30;
	public static final int DW_TAG_thrown_type = 0x31;
	public static final int DW_TAG_try_block = 0x32;
	public static final int DW_TAG_variant_part = 0x33;
	public static final int DW_TAG_variable = 0x34;
	public static final int DW_TAG_volatile_type = 0x35;
	public static final int DW_TAG_dwarf_procedure = 0x36;
	public static final int DW_TAG_restrict_type = 0x37;
	public static final int DW_TAG_interface_type = 0x38;
	public static final int DW_TAG_namespace = 0x39;
	public static final int DW_TAG_imported_module = 0x3a;
	public static final int DW_TAG_unspecified_type = 0x3b;
	public static final int DW_TAG_partial_unit = 0x3c;
	public static final int DW_TAG_imported_unit = 0x3d;
	public static final int DW_TAG_mutable_type = 0x3e;
	public static final int DW_TAG_condition = 0x3f;
	public static final int DW_TAG_shared_type = 0x40;
	public static final int DW_TAG_type_unit = 0x41;
	public static final int DW_TAG_rvalue_reference_type = 0x42;
	public static final int DW_TAG_template_alias = 0x43;
	public static final int DW_TAG_call_site = 0x48;
	public static final int DW_TAG_call_site_parameter = 0x49;
	public static final int DW_TAG_lo_user = 0x4080;
	public static final int DW_TAG_gnu_call_site = 0x4109;
	public static final int DW_TAG_gnu_call_site_parameter = 0x410a;
	public static final int DW_TAG_hi_user = 0xffff;

}
