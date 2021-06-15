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

/**
 * GDB breakpoint disposition
 * 
 * GDB allows the user to specify what happens to a breakpoint after it has been hit. Different
 * targets may also have different default/preferred behavior. The breakpoint may remain, or it may
 * be deleted after the target stops at that breakpoint.
 */
public enum GdbBreakpointDisp {
	/**
	 * The breakpoint should remain until deleted by the user
	 */
	KEEP("keep"),
	/**
	 * The breakpoint should be deleted once it is hit
	 */
	DEL("del"),
	/**
	 * Some disposition unknown to the manager
	 */
	OTHER("<OTHER>");

	/**
	 * Parse a disposition from a GDB/MI breakpoint information block
	 * 
	 * @param string the value of disposition parsed
	 * @return the enum constant, or {@link #OTHER} if unrecognized
	 */
	public static GdbBreakpointDisp fromStr(String string) {
		try {
			return valueOf(string.toUpperCase());
		}
		catch (IllegalArgumentException e) {
			return OTHER;
		}
	}

	private final String name;

	private GdbBreakpointDisp(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return name;
	}

	public String getName() {
		return name;
	}
}
