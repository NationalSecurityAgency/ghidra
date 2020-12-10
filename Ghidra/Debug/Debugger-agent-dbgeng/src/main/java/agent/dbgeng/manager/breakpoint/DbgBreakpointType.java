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
package agent.dbgeng.manager.breakpoint;

/**
 * The type of Dbg breakpoint
 */
public enum DbgBreakpointType {
	/**
	 * A software execution breakpoint, usually set via {@code break}
	 */
	BREAKPOINT,
	/**
	 * A hardware execution breakpoint, usually set via {@code hbreak}
	 */
	HW_BREAKPOINT,
	/**
	 * A debug printf point, usually set via {@code dprint}
	 */
	DPRINTF,
	/**
	 * A hardware (write) watchpoint, usually set via {@code watch}
	 */
	HW_WATCHPOINT,
	/**
	 * A read watchpoint, usually set via {@code rwatch}
	 */
	READ_WATCHPOINT,
	/**
	 * An access (r/w) watchpoint, usually set via {@code awatch}
	 */
	ACCESS_WATCHPOINT,
	/**
	 * Some type not known to the manager
	 */
	OTHER;

	/**
	 * Parse a type from a Dbg/MI breakpoint information block
	 * 
	 * @param string the value of type parsed
	 * @return the enum constant, or {@link #OTHER} if unrecognized
	 */
	public static DbgBreakpointType fromStr(String string) {
		try {
			return valueOf(string);
		}
		catch (IllegalArgumentException e) {
			return OTHER;
		}
	}
}
