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
package ghidra.app.util.demangler;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.*;

/**
 * A class to represent a demangled structure
 */
public class DemangledStructure extends DemangledDataType {

	/**
	 * A field of a {@link DemangledStructure}
	 * 
	 * @param name The field name
	 * @param description The field description
	 * @param type The field {@link DemangledDataType type}
	 */
	public record Field(String name, String description, DemangledDataType type) {}

	private List<Field> fields = new ArrayList<>();
	private String categoryPath;
	private boolean packed;

	/**
	 * Creates a new {@link DemangledStructure}
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The structure name
	 * @param categoryPath The structure category path
	 * @param packed True if the structure should be packed; otherwise, false
	 */
	public DemangledStructure(String mangled, String originalDemangled, String name,
			String categoryPath, boolean packed) {
		super(mangled, originalDemangled, name);
		setStruct();
		this.categoryPath = categoryPath;
		this.packed = packed;
	}

	/**
	 * Adds a new field to the structure. The field will not have a description.
	 * 
	 * @param name The field name
	 * @param type The field {@link DemangledDataType type}
	 */
	public void addField(String name, DemangledDataType type) {
		fields.add(new Field(name, null, type));
	}

	/**
	 * Adds a new field to the structure
	 * 
	 * @param name The field name
	 * @param description The field description
	 * @param type The field {@link DemangledDataType type}
	 */
	public void addField(String name, String description, DemangledDataType type) {
		fields.add(new Field(name, description, type));
	}

	/**
	 * Gets the {@link List} of {@link Field}s
	 * 
	 * @return The {@link List} of {@link Field}s
	 */
	public List<Field> getFields() {
		return fields;
	}

	@Override
	public DataType getDataType(DataTypeManager dataTypeManager) {
		String name = getName();
		if (name == null) {
			return DataType.DEFAULT;
		}

		StructureDataType struct = new StructureDataType(name, 0, dataTypeManager);
		for (Field field : fields) {
			struct.add(field.type().getDataType(dataTypeManager), field.name(),
				field.description());
		}
		struct.setPackingEnabled(packed);
		struct.setCategoryPath(new CategoryPath(categoryPath));
		return struct;
	}

}
