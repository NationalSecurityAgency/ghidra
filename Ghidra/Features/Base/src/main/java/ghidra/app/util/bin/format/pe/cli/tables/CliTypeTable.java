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
package ghidra.app.util.bin.format.pe.cli.tables;

/**
 * Possible Metadata table types.
 */
public enum CliTypeTable {
	Module(0x00),
	TypeRef(0x01),
	TypeDef(0x02),
	Field(0x04),
	MethodDef(0x06),
	Param(0x08),
	InterfaceImpl(0x09),
	MemberRef(0x0a),
	Constant(0x0b),
	CustomAttribute(0x0c),
	FieldMarshal(0x0d),
	DeclSecurity(0x0e),
	ClassLayout(0x0f),
	FieldLayout(0x10),
	StandAloneSig(0x11),
	EventMap(0x12),
	Event(0x14),
	PropertyMap(0x15),
	Property(0x17),
	MethodSemantics(0x18),
	MethodImpl(0x19),
	ModuleRef(0x1a),
	TypeSpec(0x1b),
	ImplMap(0x1c),
	FieldRVA(0x1d),
	Assembly(0x20),
	AssemblyProcessor(0x21),
	AssemblyOS(0x22),
	AssemblyRef(0x23),
	AssemblyRefProcessor(0x24),
	AssemblyRefOS(0x25),
	File(0x26),
	ExportedType(0x27),
	ManifestResource(0x28),
	NestedClass(0x29),
	GenericParam(0x2a),
	MethodSpec(0x2b),
	GenericParamConstraint(0x2c);

	private final int id;

	/**
	 * Creates a new table type from the given ID.
	 * 
	 * @param id The ID of the table type to create.
	 */
	private CliTypeTable(int id) {
		this.id = id;
	}

	/**
	 * Gets the ID associated with this table type.
	 * 
	 * @return The ID associated with this table type.
	 */
	public int id() {
		return id;
	}

	/**
	 * Gets a table type from the given ID.
	 * 
	 * @param id The ID of the table type to get.
	 * @return A table type with the given ID, or null if one doesn't exist.
	 */
	public static CliTypeTable fromId(int id) {
		CliTypeTable[] values = CliTypeTable.values();
		for (CliTypeTable value : values) {
			if (value.id == id)
				return value;
		}
		return null;
	}
}
