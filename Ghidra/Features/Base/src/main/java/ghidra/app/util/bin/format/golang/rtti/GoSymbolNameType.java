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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public enum GoSymbolNameType {
	UNKNOWN,
	FUNC,
	METHOD_WRAPPER,
	ANON_FUNC, // ie. lambda
	DEFER_WRAPPER,
	GO_WRAPPER,
	DATA_TYPE;

	public boolean isClosure() {
		return switch (this) {
			case ANON_FUNC, DEFER_WRAPPER, GO_WRAPPER -> true;
			default -> false;
		};
	}

	private static final Pattern P = Pattern.compile(".*?([a-z]+)[0-9]+(\\.[0-9]+)?$");

	public static GoSymbolNameType fromNameWithDashSuffix(String name) {
		if (name.endsWith("-fm")) {
			return METHOD_WRAPPER;
		}
		return FUNC;
	}

	public static GoSymbolNameType fromNameSuffix(String suffix) {
		if (suffix == null) {
			return FUNC;
		}
		Matcher m = P.matcher(suffix);
		if (m.matches()) {
			return switch (m.group(1)) {
				case "func" -> ANON_FUNC;
				case "deferwrap" -> DEFER_WRAPPER;
				case "gowrap" -> GO_WRAPPER;
				default -> UNKNOWN;
			};
		}
		return UNKNOWN;
	}
}
