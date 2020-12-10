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
package agent.gdb.manager.breakpoint;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The type of GDB breakpoint
 */
public enum GdbBreakpointType {
	/**
	 * A software execution breakpoint, usually set via {@code break}
	 */
	BREAKPOINT("breakpoint", false),
	/**
	 * A hardware execution breakpoint, usually set via {@code hbreak}
	 */
	HW_BREAKPOINT("hw breakpoint", false),
	/**
	 * A debug printf point, usually set via {@code dprint}
	 */
	DPRINTF("dprintf", false),
	/**
	 * A hardware (write) watchpoint, usually set via {@code watch}
	 */
	HW_WATCHPOINT("hw watchpoint", true),
	/**
	 * A read watchpoint, usually set via {@code rwatch}
	 */
	READ_WATCHPOINT("read watchpoint", true),
	/**
	 * An access (r/w) watchpoint, usually set via {@code awatch}
	 */
	ACCESS_WATCHPOINT("acc watchpoint", true),
	/**
	 * Some type not known to the manager
	 */
	OTHER("<OTHER>", false);

	public static final Map<String, GdbBreakpointType> BY_NAME =
		List.of(values()).stream().collect(Collectors.toMap(v -> v.getName(), v -> v));

	/**
	 * Parse a type from a GDB/MI breakpoint information block
	 * 
	 * @param string the value of type parsed
	 * @return the enum constant, or {@link #OTHER} if unrecognized
	 */
	public static GdbBreakpointType fromStr(String string) {
		return BY_NAME.getOrDefault(string, OTHER);
	}

	private final String name;
	private final boolean isWatchpoint;

	private GdbBreakpointType(String name, boolean isWatchpoint) {
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
