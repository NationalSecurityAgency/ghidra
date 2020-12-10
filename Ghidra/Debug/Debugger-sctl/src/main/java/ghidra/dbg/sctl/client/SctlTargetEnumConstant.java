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

import ghidra.dbg.util.PathUtils;

public class SctlTargetEnumConstant extends SctlTargetDataTypeMember {
	protected static String indexConst(long value) {
		return PathUtils.makeIndex(value);
	}

	protected static String keyConst(int position) {
		return PathUtils.makeKey(indexConst(position));
	}

	public SctlTargetEnumConstant(SctlTargetNamedDataType<?, ?> type, int position, long value,
			String memberName) {
		super(type, keyConst(position), position, value, memberName, type, "EnumConstant");
	}

	@Override
	public String toString() {
		String[] parts = parent.module.getIndex().split("/");
		return String.format("<SCTL enum constant: %s::%s = %d>", parts[parts.length - 1],
			memberName, position);
	}
}
