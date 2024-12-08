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

import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;

/**
 * Base class for all DWARF attribute value implementations.
 */
public abstract class DWARFAttributeValue {

	protected final DWARFAttributeDef<?> def;

	public DWARFAttributeValue(DWARFAttributeDef<?> def) {
		this.def = def;
	}

	public DWARFForm getAttributeForm() {
		return def.getAttributeForm();
	}
	
	public String getAttributeName() {
		return def.getAttributeName();
	}

	public String toString(DWARFCompilationUnit compilationUnit) {
		return toString();
	}

}
