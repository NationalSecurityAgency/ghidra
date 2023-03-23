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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.nio.charset.Charset;

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.PcodeDataTypeManager;

/**
 * Class for manipulating "deferred" constant systems like the java virtual machine constant pool
 *
 */
public abstract class ConstantPool {
	public static final int PRIMITIVE = 0;			// Constant -value- of datatype -type-
	public static final int STRING_LITERAL = 1;		// Constant reference to string in -token-
	public static final int CLASS_REFERENCE = 2;	// Reference to (system level) class object
	public static final int POINTER_METHOD = 3;		// Pointer to a method, name in -token-, signature in -type-
	public static final int POINTER_FIELD = 4;		// Pointer to a field, name in -token-, datatype in -type-
	public static final int ARRAY_LENGTH = 5;		// Integer length, -token- is language specific indicator, -type- is integral type
	public static final int INSTANCE_OF = 6;		// boolean value, -token- is language specific indicator, -type- is boolean type
	public static final int CHECK_CAST = 7;			// Pointer to object, new name in -token-, new datatype in -type-

	public static class Record {
		public int tag;			// The type of the record
		public String token;		// Name or token associated with object
		public long value;			// Primitive value of the object (if tag == PRIMITIVE)
		public byte[] byteData;
		public DataType type;
		public boolean isConstructor = false;

		public void encode(Encoder encoder, long ref, PcodeDataTypeManager dtmanage)
				throws IOException {
			encoder.openElement(ELEM_CPOOLREC);
			encoder.writeUnsignedInteger(ATTRIB_REF, ref);
			if (tag == STRING_LITERAL) {
				encoder.writeString(ATTRIB_TAG, "string");
			}
			else if (tag == CLASS_REFERENCE) {
				encoder.writeString(ATTRIB_TAG, "classref");
			}
			else if (tag == POINTER_METHOD) {
				encoder.writeString(ATTRIB_TAG, "method");
			}
			else if (tag == POINTER_FIELD) {
				encoder.writeString(ATTRIB_TAG, "field");
			}
			else if (tag == ARRAY_LENGTH) {
				encoder.writeString(ATTRIB_TAG, "arraylength");
			}
			else if (tag == INSTANCE_OF) {
				encoder.writeString(ATTRIB_TAG, "instanceof");
			}
			else if (tag == CHECK_CAST) {
				encoder.writeString(ATTRIB_TAG, "checkcast");
			}
			else {
				encoder.writeString(ATTRIB_TAG, "primitive");
			}
			if (isConstructor) {
				encoder.writeBool(ATTRIB_CONSTRUCTOR, true);
			}
			if (tag == PRIMITIVE) {
				encoder.openElement(ELEM_VALUE);
				encoder.writeUnsignedInteger(ATTRIB_CONTENT, value);
				encoder.closeElement(ELEM_VALUE);
			}
			if (byteData != null) {
				encoder.openElement(ELEM_DATA);
				encoder.writeSignedInteger(ATTRIB_LENGTH, byteData.length);
				StringBuilder buf = new StringBuilder();
				int wrap = 0;
				for (byte val : byteData) {
					int hival = (val >> 4) & 0xf;
					char hi = (char) ((hival > 9) ? hival - 10 + 'a' : hival + '0');
					int loval = val & 0xf;
					char lo = (char) ((loval > 9) ? loval - 10 + 'a' : loval + '0');
					buf.append(hi).append(lo).append(' ');
					wrap += 1;
					if (wrap > 15) {
						buf.append('\n');
						wrap = 0;
					}
				}
				encoder.writeString(ATTRIB_CONTENT, buf.toString());
				encoder.closeElement(ELEM_DATA);
			}
			else {
				encoder.openElement(ELEM_TOKEN);
				encoder.writeString(ATTRIB_CONTENT, token);
				encoder.closeElement(ELEM_TOKEN);
			}
			dtmanage.encodeTypeRef(encoder, type, type.getLength());
			encoder.closeElement(ELEM_CPOOLREC);
		}

		public void setUTF8Data(String val) {
			byteData = val.getBytes(Charset.forName("UTF-8"));
		}
	}

	public abstract Record getRecord(long[] ref);
}
