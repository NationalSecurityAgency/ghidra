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
package ghidra.app.util.bin.format.dwarf4.attribs;

import ghidra.app.util.bin.format.dwarf4.DWARFAbbreviation;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFForm;

/**
 * DWARF indirect attribute.
 * <p>
 * Holds a reference to an actual {@link DWARFAttributeValue} instance and its {@link DWARFForm type}.
 * <p>
 * Used with DW_FORM_indirect attributes that encode the {@link DWARFForm form type} of the attribute
 * value inline instead of in the DIE's {@link DWARFAbbreviation abbreviation}.
 * <p>
 */
public class DWARFIndirectAttribute implements DWARFAttributeValue {
	private DWARFAttributeValue value;
	private DWARFForm form;

	public DWARFIndirectAttribute(DWARFAttributeValue value, DWARFForm form) {
		this.value = value;
		this.form = form;
	}

	public DWARFAttributeValue getValue() {
		return value;
	}

	public DWARFForm getForm() {
		return form;
	}
}
