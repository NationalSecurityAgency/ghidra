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
package agent.lldb.manager.breakpoint;

import java.util.*;

import SWIG.*;
import agent.lldb.lldb.DebugBreakpoint.BreakAccess;
import agent.lldb.lldb.DebugClient;
import ghidra.comm.util.BitmaskSet;

public class LldbBreakpointInfo {

	private Object info;
	private SBProcess proc;

	private Long offset;
	private String expression;
	private final List<SBBreakpointLocation> locations;

	/**
	 * Construct lldb breakpoint information
	 * 
	 * @param number the lldb-assigned breakpoint number
	 * @param type the type of breakpoint
	 * @param disp the breakpoint disposition
	 * @param loc the location of the breakpoint
	 * @param pending if pending, the location that is not yet resolved
	 * @param enabled true if the breakpoint is enabled, false otherwise
	 * @param times the number of times the breakpoint has been hit
	 * @param locations the resolved address(es) of this breakpoint
	 */
	public LldbBreakpointInfo(SBBreakpoint bpt, boolean enabled) {
		this(bpt, bpt.GetTarget().GetProcess());
		bpt.SetEnabled(enabled);
	}

	public LldbBreakpointInfo(SBBreakpoint bpt, SBProcess process) {
		this.info = bpt;
		this.proc = process;
		locations = new ArrayList<>();
		for (int i = 0; i < bpt.GetNumLocations(); i++) {
			locations.add(bpt.GetLocationAtIndex(i));
		}
	}

	public LldbBreakpointInfo(SBWatchpoint wpt, SBProcess process) {
		this.info = wpt;
		this.proc = process;
		locations = new ArrayList<>();
	}

	public String getId() {
		return DebugClient.getId(info);
	}

	@Override
	public int hashCode() {
		return Objects.hash(getId());
	}

	@Override
	public String toString() {
		return DebugClient.getId(info);
	}

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof LldbBreakpointInfo))) {
			return false;
		}
		LldbBreakpointInfo that = (LldbBreakpointInfo) obj;
		if (this.getId() != that.getId()) {
			return false;
		}
		return true;
	}

	/**
	 * Get the breakpoint disposition, i.e., what happens to the breakpoint once it has been hit
	 * 
	 * @return the disposition
	 */
	public LldbBreakpointDisp getDisp() {
		return LldbBreakpointDisp.KEEP;
	}

	/**
	 * Get the offset expression of the breakpoint
	 * 
	 * @return the location
	 */
	public String getExpression() {
		return expression;
	}

	/**
	 * Get the size of the breakpoint
	 * 
	 * @return the size
	 */
	public int getSize() {
		return 1;
	}

	/**
	 * Get the access of the breakpoint
	 * 
	 * @return the size
	 */
	public BitmaskSet<BreakAccess> getAccess() {
		return null;//access;
	}

	/**
	 * Get the offset of this breakpoint
	 * 
	 * <p>
	 * Note if the offset was given as an expression, but it hasn't been resolved, this will return
	 * {@code null}.
	 * 
	 * @return the offset, or {@code null}
	 */
	public Long getOffset() {
		return offset;
	}

	/**
	 * Check if the breakpoint is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	public boolean isEnabled() {
		if (info instanceof SBBreakpoint) {
			return ((SBBreakpoint) info).IsEnabled();
		}
		else {
			return ((SBWatchpoint) info).IsEnabled();
		}
	}

	/**
	 * Get the number of times the breakpoint has been hit
	 * 
	 * @return the hit count
	 */
	public long getTimes() {
		if (info instanceof SBBreakpoint) {
			return ((SBBreakpoint) info).GetHitCount();
		}
		else {
			return ((SBWatchpoint) info).GetHitCount();
		}
	}

	/**
	 * Get a list of resolved addresses
	 * 
	 * <p>
	 * The effective locations may change for a variety of reasons. Most notable, a new module may
	 * be loaded, having location(s) that match the desired location of this breakpoint. The binary
	 * addresses within will become new effective locations of this breakpoint.
	 * 
	 * @return the list of locations at the time the breakpoint information was captured
	 */
	public List<SBBreakpointLocation> getLocations() {
		return locations;
	}

	public Object getBreakpoint() {
		return info;
	}

	public void setBreakpoint(Object info) {
		this.info = info;
	}

	public SBProcess getProc() {
		return proc;
	}

	public int getEventThread() {
		if (info instanceof SBBreakpoint) {
			return ((SBBreakpoint) info).GetThreadID().intValue();
		}
		else {
			return -1;
		}
	}

	public long getAddressAsLong() {
		if (info instanceof SBBreakpoint) {
			return locations.get(0).GetLoadAddress().longValue();
		}
		else {
			return ((SBWatchpoint) info).GetWatchAddress().longValue();
		}
	}
}
