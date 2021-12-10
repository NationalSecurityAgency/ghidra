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
package ghidra.file.formats.android.dex.format;

import java.lang.reflect.Field;

public final class ValueFormats {

	public final static byte VALUE_BYTE = 0x00;// (none; must be 0) ubyte[1] signed one-byte integer value
	public final static byte VALUE_SHORT = 0x02;// size - 1 (0...1) ubyte[size] signed two-byte integer value, sign-extended
	public final static byte VALUE_CHAR = 0x03;// size - 1 (0...1) ubyte[size] unsigned two-byte integer value, zero-extended
	public final static byte VALUE_INT = 0x04;// size - 1 (0...3) ubyte[size] signed four-byte integer value, sign-extended
	public final static byte VALUE_LONG = 0x06;// size - 1 (0...7) ubyte[size] signed eight-byte integer value, sign-extended
	public final static byte VALUE_FLOAT = 0x10;// size - 1 (0...3) ubyte[size] four-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 32-bit floating point value
	public final static byte VALUE_DOUBLE = 0x11;// size - 1 (0...7) ubyte[size] eight-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 64-bit floating point value
	public final static byte VALUE_STRING = 0x17;// size - 1 (0...3) ubyte[size] unsigned (zero-extended) four-byte integer value, interpreted as an index into the string_ids section and representing a
	// string value
	public final static byte VALUE_TYPE = 0x18;// size - 1 (0...3) ubyte[size] unsigned (zero-extended) four-byte integer value, interpreted as an index into the type_ids section and representing a
	// reflective type/class value
	public final static byte VALUE_FIELD = 0x19;// size - 1 (0...3) ubyte[size] unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing a
	// reflective field value
	public final static byte VALUE_METHOD = 0x1a;// size - 1 (0...3) ubyte[size] unsigned (zero-extended) four-byte integer value, interpreted as an index into the method_ids section and representing a
	// reflective method value
	public final static byte VALUE_ENUM = 0x1b;// size - 1 (0...3) ubyte[size] unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing the
	// value of an enumerated type constant
	public final static byte VALUE_ARRAY = 0x1c;// (none; must be 0) encoded_array an array of values, in the format specified by "encoded_array format" below. The size of the value is implicit in the
	// encoding.
	public final static byte VALUE_ANNOTATION = 0x1d;// (none; must be 0) encoded_annotation a sub-annotation, in the format specified by "encoded_annotation format" below. The size of the value is
	// implicit in the encoding.
	public final static byte VALUE_NULL = 0x1e;// (none; must be 0) (none) null reference value
	public final static byte VALUE_BOOLEAN = 0x1f;// boolean (0...1) (none) one-bit value; 0 for false and 1 for true. The bit is represented in the value_arg.

	public final static String toString(byte value) {
		try {
			Field[] fields = ValueFormats.class.getDeclaredFields();
			for (Field field : fields) {
				if (field.getByte(null) == value) {
					return field.getName();
				}
			}
		}
		catch (Exception e) {
			// ignore
		}
		return "Value:" + value;
	}

}
