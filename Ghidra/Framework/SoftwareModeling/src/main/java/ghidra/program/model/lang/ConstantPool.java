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

import java.nio.charset.Charset;

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.util.xml.SpecXmlUtils;

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

		public StringBuilder build(long ref, PcodeDataTypeManager dtmanage) {
			StringBuilder buf = new StringBuilder();
			buf.append("<cpoolrec");
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "ref", ref);
			if (tag == STRING_LITERAL) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "string");
			}
			else if (tag == CLASS_REFERENCE) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "classref");
			}
			else if (tag == POINTER_METHOD) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "method");
			}
			else if (tag == POINTER_FIELD) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "field");
			}
			else if (tag == ARRAY_LENGTH) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "arraylength");
			}
			else if (tag == INSTANCE_OF) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "instanceof");
			}
			else if (tag == CHECK_CAST) {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "checkcast");
			}
			else {
				SpecXmlUtils.encodeStringAttribute(buf, "tag", "primitive");
			}
			if (isConstructor) {
				SpecXmlUtils.encodeBooleanAttribute(buf, "constructor", true);
			}
			buf.append(">\n");
			if (tag == PRIMITIVE) {
				buf.append("<value>");
				buf.append(SpecXmlUtils.encodeUnsignedInteger(value));
				buf.append("</value>\n");
			}
			if (byteData != null) {
				buf.append("<data length=\"").append(byteData.length).append("\">\n");
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
				buf.append("</data>\n");
			}
			else {
				buf.append("<token>");
				SpecXmlUtils.xmlEscape(buf, token);
				buf.append("</token>\n");
			}
			buf.append(dtmanage.buildTypeRef(type, type.getLength()));
			buf.append("</cpoolrec>\n");
			return buf;
		}

		public void setUTF8Data(String val) {
			byteData = val.getBytes(Charset.forName("UTF-8"));
		}
	}

	public abstract Record getRecord(long[] ref);
}
