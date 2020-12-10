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

@DebuggerTargetObjectIface("TypeMember")
public interface TargetDataTypeMember<T extends TargetDataTypeMember<T>>
		extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetDataTypeMember<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetDataTypeMember.class;

	String POSITION_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "position";
	String MEMBER_NAME_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "member_name";
	String OFFSET_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "offset";
	String DATA_TYPE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "data_type";

	/**
	 * The position of the member in the composite
	 * 
	 * @return the position
	 */
	default int getPosition() {
		return getTypedAttributeNowByName(POSITION_ATTRIBUTE_NAME, Integer.class, -1);
	}

	default String getMemberName() {
		return getTypedAttributeNowByName(MEMBER_NAME_ATTRIBUTE_NAME, String.class, "");
	}

	default long getOffset() {
		return getTypedAttributeNowByName(OFFSET_ATTRIBUTE_NAME, Long.class, -1L);
	}

	default TargetDataType getDataType() {
		return getTypedAttributeNowByName(DATA_TYPE_ATTRIBUTE_NAME, TargetDataType.class, null);
	}
}
