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
package ghidra.comm.packet.err;

import java.lang.reflect.Field;
import java.util.List;

import ghidra.comm.packet.annot.TypedByLookahead;
import ghidra.comm.packet.fields.PacketField;

/**
 * Occurs during decode when a constant field does not match the decoded value
 * 
 * Static final fields may be annotated with {@link PacketField}, causing them to be encoded and
 * decoded the same as any other field, with two exceptions. When decoding final fields with
 * countable elements, the codec expects to decode the same number of elements. If the decoded value
 * does not match the constant value, the packet is considered malformed and this exception is
 * thrown.
 * 
 * This exception differs from {@link InvalidPacketException} in that it deals in field values, not
 * in encoding formats. It is also used by {@link TypedByLookahead} to distinguish sub-packet types.
 */
public class PacketFieldValueMismatchException extends PacketDecodeException {
	public PacketFieldValueMismatchException(Field field, Object req, Object dec) {
		super(field + " must decode with value " + req + ". Got " + dec);
	}

	public PacketFieldValueMismatchException(Field field, List<?> req, Object dec) {
		super(field + " must decode with a value from " + req + ". Got " + dec);
	}
}
