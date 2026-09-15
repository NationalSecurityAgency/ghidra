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

import java.util.Objects;

import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.DebugInfoEntry;

/**
 * Represents an attribute contained in a DIE.
 */
public class DWARFAttribute {

	protected final DebugInfoEntry die;
	protected final DWARFAttributeId.AttrDef def;
	protected final DWARFAttributeValue value;

	public DWARFAttribute(DebugInfoEntry die, DWARFAttributeId.AttrDef def,
			DWARFAttributeValue value) {
		this.die = die;
		this.def = def;
		this.value = value;
	}

	/**
	 * {@return the DIE that contains this attribute}
	 */
	public DebugInfoEntry getDIE() {
		return die;
	}

	/**
	 * {@return the compilation unit that contains the attribute's DIE}
	 */
	public DWARFCompilationUnit getCU() {
		return die.getCompilationUnit();
	}

	/**
	 * {@return the value of this attribute}
	 */
	public DWARFAttributeValue getValue() {
		return value;
	}

	/**
	 * {@return the value of this attribute, as a specific type}
	 * @param <T> expected type of the attribute value 
	 * @param clazz class of the expected type of the attribute value
	 */
	public <T extends DWARFAttributeValue> T getValue(Class<T> clazz) {
		if (clazz.isAssignableFrom(value.getClass())) {
			return clazz.cast(value);
		}
		return null;
	}

	/**
	 * {@return string name of this attribute's identifier (eg. "DW_AT_high_pc")}
	 */
	public String getAttributeName() {
		return def.getAttributeName();
	}

	/**
	 * {@return the serialization format identifier of this attribute (eg. DW_FORM_ref4)}
	 */
	public DWARFForm getAttributeForm() {
		return def.getAttributeForm();
	}

	/**
	 * {@return the value of this attribute, as a formatted string}
	 */
	public String getValueString() {
		return value.getValueString(die.getCompilationUnit(), def);
	}

	@Override
	public String toString() {
		return "%s : %s = %s".formatted(getAttributeName(), getAttributeForm(), getValueString());
	}

	@Override
	public int hashCode() {
		return Objects.hash(def, die, value);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DWARFAttribute)) {
			return false;
		}
		DWARFAttribute other = (DWARFAttribute) obj;
		return Objects.equals(def, other.def) && Objects.equals(die, other.die) &&
			Objects.equals(value, other.value);
	}

}
