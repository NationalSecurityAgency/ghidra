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

import java.util.*;

import agent.gdb.manager.parsing.GdbParsingUtils;

/**
 * A location of a breakpoint
 * 
 * Some breakpoint information blocks list multiple locations. Keeping this information in a
 * separate object allows the parsing and tracking of these locations. Usually multiple locations
 * are presented by GDB when a single location specification resolves to multiple addresses.
 */
public class GdbBreakpointLocation {
	public static final String WATCHPOINT_LOCATION_PREFIX = "-location ";

	private final long number;
	private final long sub;
	private final boolean enabled;
	private final String addr;
	private final List<Integer> inferiorIds;

	/**
	 * Construct a breakpoint location
	 * 
	 * @param number the number of breakpoint location, i.e., {@code x} in {@code x.y}
	 * @param sub the number of the breakpoint location, i.e., {@code y} in {@code x.y}
	 * @param enabled true if the location is enabled, false otherwise
	 * @param addr the address of this location, usually resolved, but maybe not
	 * @param inferiorIds a list of inferior IDs to which this location applies
	 */
	GdbBreakpointLocation(long number, long sub, boolean enabled, String addr,
			List<Integer> inferiorIds) {
		this.number = number;
		this.sub = sub;
		this.enabled = enabled;
		this.addr = addr;
		this.inferiorIds = Collections.unmodifiableList(inferiorIds);
	}

	@Override
	public String toString() {
		return "<Loc number=" + number + "." + sub + ",enabled=" + enabled + ",addr=" + addr +
			",iids=" + inferiorIds + ">";
	}

	/**
	 * Get the breakpoint number, i.e., {@code x} in {@code x.y}
	 * 
	 * @return the breakpoint number
	 */
	public long getNumber() {
		return number;
	}

	/**
	 * If present, get the location number, i.e., {@code y} in {@code x.y}
	 * 
	 * @return the location number, or 0
	 */
	public long getSub() {
		return sub;
	}

	/**
	 * Check if the location is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Get the address, usually resolved, but maybe not
	 * 
	 * @see {@link GdbBreakpointInfo#getPending()}
	 * @return the address
	 */
	public String getAddr() {
		return addr;
	}

	/**
	 * If numerical, get the address as a long
	 * 
	 * @return the address
	 */
	public long addrAsLong() {
		return GdbParsingUtils.parsePrefixedHex(addr);
	}

	/**
	 * Get a list of inferior IDs to which this location applies
	 * 
	 * @return the list of inferiors
	 */
	public List<Integer> getInferiorIds() {
		return inferiorIds;
	}

	@Override
	public int hashCode() {
		return Objects.hash(number, sub, enabled, addr, inferiorIds);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof GdbBreakpointLocation)) {
			return false;
		}
		GdbBreakpointLocation that = (GdbBreakpointLocation) obj;
		if (this.number != that.number) {
			return false;
		}
		if (this.sub != that.sub) {
			return false;
		}
		if (this.enabled != that.enabled) {
			return false;
		}
		if (!Objects.equals(this.addr, that.addr)) {
			return false;
		}
		if (!Objects.equals(this.inferiorIds, that.inferiorIds)) {
			return false;
		}
		return true;
	}
}
