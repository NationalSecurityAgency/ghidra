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
package ghidra.app.util.bin.format.swift;

import java.util.List;

/**
 * Used to refer to a Swift section, which can have different names depending on the platform
 * 
 * @see <a href="https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/Swift.def">llvm/BinaryFormat/Swift.def</a> 
 */
public enum SwiftSection {


	BLOCK_FIELDMD("__swift5_fieldmd", "swift5_fieldmd", ".sw5flmd"),
	BLOCK_ASSOCTY("__swift5_assocty", "swift5_assocty", ".sw5asty"),
	BLOCK_BUILTIN("__swift5_builtin", "swift5_builtin", ".sw5bltn"),
	BLOCK_CAPTURE("__swift5_capture", "swift5_capture", ".sw5cptr"),
	BLOCK_TYPEREF("__swift5_typeref", "swift5_typeref", ".sw5tyrf"),
	BLOCK_REFLSTR("__swift5_reflstr", "swift5_reflstr", ".sw5rfst"),
	BLOCK_CONFORM("__swift5_proto", "swift5_protocol_conformances", ".sw5prtc"),
	BLOCK_PROTOCS("__swift5_protos", "swift5_protocols", ".sw5prt"),
	BLOCK_ACFUNCS("__swift5_acfuncs", "swift5_accessible_functions", ".sw5acfn"),
	BLOCK_MPENUM("__swift5_mpenum", "swift5_mpenum", ".sw5mpen"),
	BLOCK_TYPES("__swift5_types", "swift5_type_metadata", ".sw5tymd"),
	BLOCK_ENTRY("__swift5_entry", "swift5_entry", ".sw5entr"),
	BLOCK_SWIFTAST("__swift_ast", ".swift_ast", "swiftast");

	private List<String> sectionNames;
	
	/**
	 * Create a new {@link SwiftSection}
	 * 
	 * @param names The names the section goes by
	 */
	private SwiftSection(String... names) {
		sectionNames = List.of(names);
	}
	
	/**
	 * Gets a {@link List} of the {@link SwiftSection}'s names
	 * 
	 * @return A {@link List} of the {@link SwiftSection}'s names
	 */
	public List<String> getSwiftSectionNames() {
		return sectionNames;
	}
}
