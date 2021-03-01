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
package ghidra.dbg.target;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.TargetDataTypeConverter;

/**
 * A member of another data type
 * 
 * <p>
 * This is usually the child of a {@link TargetNamedDataType}, and its role in determined
 * conventionally by the actual type of the parent, and of this member's key.
 * 
 * <p>
 * TODO: Document the conventions. Most, if not all, are implemented in
 * {@link TargetDataTypeConverter}.
 */
@DebuggerTargetObjectIface("TypeMember")
public interface TargetDataTypeMember extends TargetObject {

	String POSITION_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "position";
	String MEMBER_NAME_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "member_name";
	String OFFSET_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "offset";
	String DATA_TYPE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "data_type";

	/**
	 * The position of the member in the composite
	 * 
	 * <p>
	 * A position of -1 implies the parent is not a composite or this member's role is special,
	 * e.g., the return type of a function.
	 * 
	 * @return the position
	 */
	@TargetAttributeType(name = POSITION_ATTRIBUTE_NAME, hidden = true)
	default int getPosition() {
		return getTypedAttributeNowByName(POSITION_ATTRIBUTE_NAME, Integer.class, -1);
	}

	/**
	 * The name of the member in the composite
	 * 
	 * @return the name
	 */
	@TargetAttributeType(name = MEMBER_NAME_ATTRIBUTE_NAME, required = true, hidden = true)
	default String getMemberName() {
		return getTypedAttributeNowByName(MEMBER_NAME_ATTRIBUTE_NAME, String.class, "");
	}

	/**
	 * The offset of the member in the composite
	 * 
	 * <p>
	 * For structs, this should be the offset in bytes from the base of the struct. For unions, this
	 * should likely be 0. For others, this should be absent or -1.
	 * 
	 * @return the offset
	 */
	@TargetAttributeType(name = OFFSET_ATTRIBUTE_NAME, hidden = true)
	default long getOffset() {
		return getTypedAttributeNowByName(OFFSET_ATTRIBUTE_NAME, Long.class, -1L);
	}

	/**
	 * The type of this member
	 * 
	 * @return the type
	 */
	@TargetAttributeType(name = DATA_TYPE_ATTRIBUTE_NAME, required = true, hidden = true)
	default TargetDataType getDataType() {
		return getTypedAttributeNowByName(DATA_TYPE_ATTRIBUTE_NAME, TargetDataType.class, null);
	}
}
