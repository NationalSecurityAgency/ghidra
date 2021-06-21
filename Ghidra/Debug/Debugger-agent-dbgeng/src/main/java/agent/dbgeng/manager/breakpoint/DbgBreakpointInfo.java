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

import java.util.Objects;

import agent.dbgeng.dbgeng.DebugBreakpoint;
import agent.dbgeng.dbgeng.DebugBreakpoint.*;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.DbgThread;
import ghidra.comm.util.BitmaskSet;

public class DbgBreakpointInfo {

	private DebugBreakpoint bpt;
	private DbgProcess proc;
	private DbgThread eventThread;
	private BreakFullType bptType;
	private BitmaskSet<BreakFlags> flags;
	private BreakDataParameters parameters =
		new BreakDataParameters(1, BitmaskSet.of(BreakAccess.EXECUTE));
	private BitmaskSet<BreakAccess> access;
	private int size = 1;

	private final long number;
	private boolean enabled;

	private Long offset;
	private String expression;
	//private final List<DbgBreakpointLocation> locations;

	/**
	 * Construct Dbg breakpoint information
	 * 
	 * @param number the Dbg-assigned breakpoint number
	 * @param type the type of breakpoint
	 * @param disp the breakpoint disposition
	 * @param loc the location of the breakpoint
	 * @param pending if pending, the location that is not yet resolved
	 * @param enabled true if the breakpoint is enabled, false otherwise
	 * @param times the number of times the breakpoint has been hit
	 * @param locations the resolved address(es) of this breakpoint
	 */
	public DbgBreakpointInfo(DbgBreakpointInfo oldInfo, boolean enabled) {
		this(oldInfo.getDebugBreakpoint(), oldInfo.getProc(), oldInfo.getEventThread());
		this.enabled = enabled;
	}

	public DbgBreakpointInfo(DebugBreakpoint bpt, DbgProcess proc) {
		this(bpt, proc, null);
	}

	public DbgBreakpointInfo(DebugBreakpoint bp, DbgProcess process, DbgThread thread) {
		this.setBreakpoint(bp);
		this.proc = process;
		this.eventThread = thread;
		this.number = bpt.getId();
		this.bptType = bpt.getType();
		this.flags = bpt.getFlags();
		if (bpt.getType().breakType.equals(BreakType.DATA)) {
			this.parameters = bpt.getDataParameters();
		}
		this.access = parameters.access;
		this.size = parameters.size;
		this.offset = bpt.getOffset();
		this.expression = bpt.getOffsetExpression();
	}

	@Override
	public int hashCode() {
		return Objects.hash(number, bptType, getFlags(), /*location,*/ enabled, access, getSize(),
			offset, expression);
	}

	public int getId() {
		return bpt.getId();
	}

	@Override
	public String toString() {
		return Integer.toHexString(bpt.getId());
	}
	/*
	@Override
	public String toString() {
		return "<DbgBreakpointInfo number=" + number + ",type=" + getType() + ",flags=" +
			getFlags() + ",addr=" + location + ",times=" + getTimes() + ",size=" + getSize() +
			",access=" + getAccess() + ">";
	}
	*/

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof DbgBreakpointInfo))) {
			return false;
		}
		DbgBreakpointInfo that = (DbgBreakpointInfo) obj;
		if (this.number != that.number) {
			return false;
		}
		if (this.getFlags() != that.getFlags()) {
			return false;
		}
		if (this.getSize() != that.getSize()) {
			return false;
		}
		/*if (!Objects.equals(this.location, that.location)) {
			return false;
		}*/
		if (!Objects.equals(this.expression, that.expression)) {
			return false;
		}
		if (!Objects.equals(this.offset, that.offset)) {
			return false;
		}
		if (this.enabled != that.enabled) {
			return false;
		}
		return true;
	}

	/**
	 * Get the Dbg-assigned breakpoint number
	 * 
	 * This is the key into Dbg's breakpoint table to locate the breakpoint this information
	 * describes.
	 * 
	 * @return the number
	 */
	public long getNumber() {
		return number;
	}

	/**
	 * Get the type of breakpoint
	 * 
	 * @return the type
	 */
	public DbgBreakpointType getType() {
		boolean isCode = bpt.getType().breakType.equals(BreakType.CODE);
		if (isCode) {
			return DbgBreakpointType.BREAKPOINT;
		}
		BreakDataParameters params = bpt.getDataParameters();
		if (params == null || params.access.isEmpty()) {
			return DbgBreakpointType.OTHER;
		}
		if (params.access.contains(BreakAccess.READ) && params.access.contains(BreakAccess.WRITE)) {
			return DbgBreakpointType.ACCESS_WATCHPOINT;
		}
		if (params.access.contains(BreakAccess.READ)) {
			return DbgBreakpointType.READ_WATCHPOINT;
		}
		if (params.access.contains(BreakAccess.WRITE)) {
			return DbgBreakpointType.HW_WATCHPOINT;
		}
		if (params.access.contains(BreakAccess.EXECUTE)) {
			return DbgBreakpointType.HW_BREAKPOINT;
		}
		return DbgBreakpointType.OTHER;
	}

	/**
	 * Get the breakpoint disposition, i.e., what happens to the breakpoint once it has been hit
	 * 
	 * @return the disposition
	 */
	public DbgBreakpointDisp getDisp() {
		return DbgBreakpointDisp.KEEP;
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
		return size;
	}

	/**
	 * Get the access of the breakpoint
	 * 
	 * @return the size
	 */
	public BitmaskSet<BreakAccess> getAccess() {
		return access;
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
	 * If the breakpoint is pending resolution, get the location that is pending
	 * 
	 * @return the pending location
	 */
	public String getPending() {
		return getFlags().contains(BreakFlags.DEFERRED) ? "pending" : "";
	}

	/**
	 * Check if the breakpoint is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	public boolean isEnabled() {
		return getFlags().contains(BreakFlags.ENABLED);
	}

	/**
	 * Get the number of times the breakpoint has been hit
	 * 
	 * @return the hit count
	 */
	public int getTimes() {
		return 0;
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
	/*public List<DbgBreakpointLocation> getLocations() {
		return locations;
	}*/

	public DbgBreakpointInfo withEnabled(@SuppressWarnings("hiding") boolean enabled) {
		if (isEnabled() == enabled) {
			return this;
		}
		return new DbgBreakpointInfo(this, enabled);
	}

	public DebugBreakpoint getDebugBreakpoint() {
		return bpt;
	}

	public BitmaskSet<BreakFlags> getFlags() {
		return flags;
	}

	public DbgProcess getProc() {
		return proc;
	}

	public DbgThread getEventThread() {
		return eventThread;
	}

	public void setBreakpoint(DebugBreakpoint bpt) {
		this.bpt = bpt;
		this.bptType = bpt.getType();
		this.flags = bpt.getFlags();
		this.offset = bpt.getOffset();
		this.expression = bpt.getOffsetExpression();
		if (bptType.breakType.equals(BreakType.DATA)) {
			BreakDataParameters p = bpt.getDataParameters();
			this.access = p.access;
			this.size = p.size;
		}
	}

	/*public long getAddressAsLong() {
		return locations.get(0).addrAsLong();
	}*/ // getOffset instead
}
