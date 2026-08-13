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
package ghidra.app.util.demangler.swift.datatypes;

import ghidra.app.util.bin.format.swift.SwiftTypeMetadata;
import ghidra.app.util.bin.format.swift.types.*;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangler;

/**
 * A Swift structure
 */
public class SwiftStructure extends DemangledStructure {

	/**
	 * Creates a new Swift structure
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The structure name
	 * @param namespace The structure namespace (could be null)
	 * @param demangler A {@link SwiftDemangler}
	 * @throws DemangledException if a problem occurred
	 */
	public SwiftStructure(String mangled, String originalDemangled, String name,
			Demangled namespace, SwiftDemangler demangler) throws DemangledException {
		super(mangled, originalDemangled, name,
			SwiftDataTypeUtils.getCategoryPath(namespace).getPath(), true);
		setNamespace(namespace);

		// Try to add structure fields from the type metadata
		SwiftTypeMetadata typeMetadata = demangler.getTypeMetadata();
		if (typeMetadata != null) {
			TargetTypeContextDescriptor typeDescriptor =
				typeMetadata.getTargetTypeContextDescriptors().get(name);
			if (typeDescriptor != null) {
				FieldDescriptor fieldDescriptor =
					typeDescriptor.getFieldDescriptor(typeMetadata.getFieldDescriptors());
				if (fieldDescriptor != null) {
					for (FieldRecord fieldRecord : fieldDescriptor.getFieldRecords()) {
						String mangledType = "_T" + fieldRecord.getMangledTypeName();
						Demangled demangled = demangler.getDemangled(mangledType, null);
						if (demangled instanceof DemangledDataType ddt) {
							addField(fieldRecord.getFieldName(), fieldRecord.getDescription(), ddt);
						}
					}
				}
			}
		}
	}
}
