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
 * DWARF numeric attribute.
 * <p>
 * Use this class instead of {@link DWARFAmbigNumericAttribute} when the signed-ness
 * of the raw value is known when deserializing the attribute from a stream.
 * <p>
 * Use {@link DWARFAmbigNumericAttribute} when the signed-ness of the raw value is only know
 * to the code that is using the attribute value.
 */
public class DWARFNumericAttribute implements DWARFAttributeValue {
	protected final long value;

	public DWARFNumericAttribute(long value) {
		this.value = value;
	}

	public long getValue() {
		return value;
	}

	public long getUnsignedValue() {
		return value;
	}

	@Override
	public String toString() {
		return String.format("DWARFNumericAttribute: %d [%08x]", value, value);
	}
}
