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
package ghidra.app.util.bin.format.golang.rtti;

import java.util.EnumSet;
import java.util.Set;

/**
 * Bitmask flags for runtime._func (GoFuncData) flags field.
 */
public enum GoFuncFlag {

	TOPFRAME(1 << 0),		// 1
	SPWRITE(1 << 1),		// 2
	ASM(1 << 2);			// 4

	private final int value;

	private GoFuncFlag(int i) {
		this.value = i;
	}

	public int getValue() {
		return value;
	}

	public boolean isSet(int i) {
		return (i & value) != 0;
	}

	public static Set<GoFuncFlag> parseFlags(int b) {
		EnumSet<GoFuncFlag> result = EnumSet.noneOf(GoFuncFlag.class);
		for (GoFuncFlag flag : values()) {
			if (flag.isSet(b)) {
				result.add(flag);
			}
		}
		return result;
	}

}
