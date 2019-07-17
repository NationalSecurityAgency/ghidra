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
 * Stores a integer value (with ambiguous signedness) in a long, with a mask that will
 * allow the consumer at a later time to treat the value as signed or unsigned.
 * <p>
 * When supplied with a long value that was originally a smaller integer with its high-bit
 * set, java will sign-extend the value to 64 bits.  To treat this as an unsigned
 * value, the mask needs to match the bitwidth of the supplied value, and is used to return 
 * the relevant number of bits from the value. (See NumberUtil.UNSIGNED_BYTE_MASK, etc)
 * <p>
 * This allows us to simplify the storage of a variable sized int value 
 * (1 byte, 2 byte, 4 byte, 8 byte) using just a 8 byte long and an 8 byte mask.
 */
public class DWARFAmbigNumericAttribute extends DWARFNumericAttribute {
	private final long mask;

	public DWARFAmbigNumericAttribute(long value, long mask) {
		super(value);
		this.mask = mask;
	}

	@Override
	public long getUnsignedValue() {
		return value & mask;
	}

	@Override
	public String toString() {
		return String.format("DWARFAmbigNumericAttribute: natural=%d [%08x], unsigned=%s [%08x]",
			value, value, Long.toUnsignedString(getUnsignedValue()), getUnsignedValue());
	}

}
