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
package ghidra.dbg.sctl.client;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.TargetDataTypeMember;
import ghidra.dbg.target.TargetObject;

public class SctlTargetDataTypeMember
		extends DefaultTargetObject<TargetObject, SctlTargetNamedDataType<?, ?>>
		implements TargetDataTypeMember<SctlTargetDataTypeMember> {

	protected final int position;
	protected final long offset;
	protected final String memberName;
	protected final TargetDataType dataType;

	public SctlTargetDataTypeMember(SctlTargetNamedDataType<?, ?> type, String key, int position,
			long offset, String memberName, TargetDataType dataType, String typeHint) {
		super(type.client, type, key, typeHint);

		this.position = position;
		this.offset = offset;
		this.memberName = memberName;
		this.dataType = dataType;

		changeAttributes(List.of(), Map.of( //
			POSITION_ATTRIBUTE_NAME, position, //
			MEMBER_NAME_ATTRIBUTE_NAME, memberName, //
			OFFSET_ATTRIBUTE_NAME, offset, //
			DATA_TYPE_ATTRIBUTE_NAME, dataType //
		), "Initialized");
	}

	@Override
	public int getPosition() {
		return position;
	}

	@Override
	public String getMemberName() {
		return memberName;
	}

	@Override
	public long getOffset() {
		return offset;
	}

	@Override
	public TargetDataType getDataType() {
		return dataType;
	}
}
