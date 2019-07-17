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

/**
 * DWARF boolean attribute.
 */
public class DWARFBooleanAttribute implements DWARFAttributeValue {
	public static final DWARFBooleanAttribute TRUE = new DWARFBooleanAttribute(true);
	public static final DWARFBooleanAttribute FALSE = new DWARFBooleanAttribute(false);

	public static DWARFBooleanAttribute get(boolean b) {
		return b ? TRUE : FALSE;
	}

	private final boolean value;

	public DWARFBooleanAttribute(boolean value) {
		this.value = value;
	}

	public boolean getValue() {
		return value;
	}

	@Override
	public String toString() {
		return "DWARFBooleanAttribute: " + value;
	}
}
