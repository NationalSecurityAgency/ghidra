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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.util.EnumSet;
import java.util.Set;

import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.app.util.bin.format.golang.GoVerRange;

/**
 * Enum defining the various bitflags held in a GoType's tflag
 */
public enum GoTypeFlag {

	Uncommon(1 << 0, GoVerRange.ALL),					// 1
	ExtraStar(1 << 1, GoVerRange.ALL),					// 2
	Named(1 << 2, GoVerRange.ALL),						// 4
	RegularMemory(1 << 3, GoVerRange.ALL),				// 8
	UnrolledBitmap(1 << 4, GoVerRange.parse("1.22-"));	// 16

	private final int value;
	private GoVerRange validVersions;

	GoTypeFlag(int i, GoVerRange validVersions) {
		this.value = i;
		this.validVersions = validVersions;
	}

	public int getValue() {
		return value;
	}

	public boolean isSet(int i) {
		return (i & value) != 0;
	}

	//----------------------------------------------------------

	private static final GoTypeFlag[] lookupvalues = values();

	public static boolean isValid(int b, GoVer ver) {
		int maxMask = 0;
		for (GoTypeFlag flag : lookupvalues) {
			if (flag.validVersions.contains(ver)) {
				maxMask |= flag.value;
			}
		}
		return b <= maxMask;
	}

	public static Set<GoTypeFlag> parseFlags(int b) {
		EnumSet<GoTypeFlag> result = EnumSet.noneOf(GoTypeFlag.class);
		for (GoTypeFlag flag : lookupvalues) {
			if (flag.isSet(b)) {
				result.add(flag);
			}
		}
		return result;
	}

}
