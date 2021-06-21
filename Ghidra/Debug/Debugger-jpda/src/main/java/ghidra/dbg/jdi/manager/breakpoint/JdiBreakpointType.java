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
package ghidra.dbg.jdi.manager.breakpoint;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The type of JDI breakpoint
 */
public enum JdiBreakpointType {

	BREAKPOINT("breakpoint", false),
	ACCESS_WATCHPOINT("access watchpont", true),
	MODIFICATION_WATCHPOINT("modification watchpoint", true),
	OTHER("<OTHER>", false);

	public static final Map<String, JdiBreakpointType> BY_NAME =
		List.of(values()).stream().collect(Collectors.toMap(v -> v.getName(), v -> v));

	/**
	 * Parse a type from a JDI breakpoint information block
	 * 
	 * @param string the value of type parsed
	 * @return the enum constant, or {@link #OTHER} if unrecognized
	 */
	public static JdiBreakpointType fromStr(String string) {
		return BY_NAME.getOrDefault(string, OTHER);
	}

	private final String name;
	private final boolean isWatchpoint;

	private JdiBreakpointType(String name, boolean isWatchpoint) {
		this.name = name;
		this.isWatchpoint = isWatchpoint;
	}

	@Override
	public String toString() {
		return name;
	}

	public String getName() {
		return name;
	}

	public boolean isWatchpoint() {
		return isWatchpoint;
	}
}
