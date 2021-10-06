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

import agent.gdb.manager.parsing.GdbMiParser;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils;

/**
 * Information about a GDB breakpoint
 * 
 * <p>
 * This contains the semantic processing for GDB breakpoint information. Mostly, it just stores the
 * information, but it also enumerates the locations of a breakpoint and generates the "effective"
 * breakpoints.
 * 
 * <p>
 * Note this is not a handle to the breakpoint. Rather, this is the captured information from some
 * event or request. If other commands have been executed since this information was gathered, the
 * information may be stale.
 */
public class GdbBreakpointInfo {
	private static List<Integer> parseIids(GdbMiFieldList bkpt) {
		List<Integer> iids = new ArrayList<>();
		List<String> gids = bkpt.getListOf(String.class, "thread-groups");
		if (gids == null) {
			return null;
		}
		for (String gid : gids) {
			iids.add(GdbParsingUtils.parseInferiorId(gid));
		}
		return iids;
	}

	/**
	 * Process a parsed GDB breakpoint information block
	 * 
	 * <p>
	 * The passed info should be the field list containing "{@code bkpt={...}}."
	 * 
	 * <p>
	 * It may also contain {@code wpt}, {@code hw-awpt}, or {@code hw-rwpt}, in which case the
	 * "parsed info" is synthesized to match what would be given by {@code -break-list} for that
	 * watchpoint.
	 * 
	 * @param info the parsed information block
	 * @param curIid in case of a watchpoint, the current inferior id
	 * @return the processed GDB breakpoint information
	 */
	public static GdbBreakpointInfo parse(GdbMiFieldList info, Integer curIid) {
		GdbMiFieldList bkpt = info.getFieldList("bkpt");
		if (bkpt != null) {
			return parseBkpt(bkpt, parseLocations(info), curIid);
		}
		GdbMiFieldList wpt = info.getFieldList("wpt");
		if (wpt != null) {
			return parseWpt(wpt, GdbBreakpointType.HW_WATCHPOINT,
				GdbBreakpointType.HW_WATCHPOINT.getName(), curIid);
		}
		GdbMiFieldList hwAWpt = info.getFieldList("hw-awpt");
		if (hwAWpt != null) {
			return parseWpt(hwAWpt, GdbBreakpointType.ACCESS_WATCHPOINT,
				GdbBreakpointType.ACCESS_WATCHPOINT.getName(), curIid);
		}
		GdbMiFieldList hwRWpt = info.getFieldList("hw-rwpt");
		if (hwRWpt != null) {
			return parseWpt(hwRWpt, GdbBreakpointType.READ_WATCHPOINT,
				GdbBreakpointType.READ_WATCHPOINT.getName(), curIid);
		}
		throw new AssertionError("No breakpoint or watchpoint in info: " + info);
	}

	/**
	 * Parse the usual {@code bkpt} fields
	 * 
	 * @param bkpt the breakpoint field list
	 * @param allLocs all (sub)locations given in the info or table body
	 * @param curIid in case of missing {@code thread-ids} field, the current inferior id
	 * @return the info
	 */
	public static GdbBreakpointInfo parseBkpt(GdbMiFieldList bkpt,
			List<GdbBreakpointLocation> allLocs, Integer curIid) {
		// TODO: A more polymorphic approach to info types?
		long number = Long.parseLong(bkpt.getString("number"));
		String typeName = bkpt.getString("type");
		GdbBreakpointType type = GdbBreakpointType.fromStr(typeName);
		GdbBreakpointDisp disp = GdbBreakpointDisp.fromStr(bkpt.getString("disp"));
		boolean enabled = "y".equals(bkpt.getString("enabled"));
		String addr = bkpt.getString("addr");
		String what = bkpt.getString("at");
		if (what == null) {
			what = bkpt.getString("what");
		}
		String catchType = bkpt.getString("catch-type");
		String origLoc = bkpt.getString("original-location");
		String pending = bkpt.getString("pending");
		int times = Integer.parseInt(bkpt.getString("times"));
		List<GdbBreakpointLocation> locations = new ArrayList<>();

		if (type == GdbBreakpointType.CATCHPOINT) {
			// no locations
		}
		else if ("<MULTIPLE>".equals(addr)) {
			allLocs.stream().filter(l -> l.getNumber() == number).forEachOrdered(locations::add);
		}
		else {
			List<Integer> iids = parseIids(bkpt);
			if (iids == null) {
				iids = curIid == null ? List.of() : List.of(curIid);
			}
			locations.add(new GdbBreakpointLocation(number, 1, true, addr, iids));
		}
		return new GdbBreakpointInfo(number, type, typeName, disp, addr, what, catchType, origLoc,
			pending, enabled, times, locations);
	}

	/**
	 * Parse watchpoint fields and synthesize the info
	 * 
	 * @param wpt the watchpoint field list
	 * @param type the type of watchpoint
	 * @param curIid the inferior id in which the watchpoint was created
	 * @return the info
	 */
	public static GdbBreakpointInfo parseWpt(GdbMiFieldList wpt, GdbBreakpointType type,
			String typeName, int curIid) {
		int number = Integer.parseInt(wpt.getString("number"));
		String origLoc = wpt.getString("exp");

		List<GdbBreakpointLocation> locs;
		if (origLoc.startsWith(GdbBreakpointLocation.WATCHPOINT_LOCATION_PREFIX)) {
			locs = List.of(new GdbBreakpointLocation(number, 1, true, null, List.of(curIid)));
		}
		else {
			locs = List.of();
		}
		return new GdbBreakpointInfo(number, type, typeName, GdbBreakpointDisp.KEEP, null, null,
			origLoc, origLoc, null, true, 0, locs);
	}

	/**
	 * Parse all (sub)locations from the given info or table body
	 * 
	 * @param info the info or table body
	 * @return all locations parsed
	 */
	public static List<GdbBreakpointLocation> parseLocations(GdbMiFieldList info) {
		List<GdbBreakpointLocation> locations = new ArrayList<>();
		for (Object obj : info.get(GdbMiParser.UNNAMED)) {
			GdbMiFieldList loc = (GdbMiFieldList) obj;
			String[] locIdParts = loc.getString("number").split("\\.");
			long locNumber = Long.parseLong(locIdParts[0]);
			long locSub = Long.parseLong(locIdParts[1]);
			boolean locEnabled = "y".equals(loc.getString("enabled"));
			String locAddr = loc.getString("addr");
			List<Integer> locIids = parseIids(loc);

			locations.add(
				new GdbBreakpointLocation(locNumber, locSub, locEnabled, locAddr, locIids));
		}
		return locations;
	}

	private final long number;
	private final GdbBreakpointType type;
	private final String typeName;
	private final GdbBreakpointDisp disp;
	private final String addr;
	private final String what;
	private final String catchType;
	private final String originalLocation;
	private final String pending;
	private final boolean enabled;
	private final int times;
	private final List<GdbBreakpointLocation> locations;

	/**
	 * Construct GDB breakpoint information
	 * 
	 * @param number the GDB-assigned breakpoint number
	 * @param type the type of breakpoint
	 * @param disp the breakpoint disposition
	 * @param addr the location of the breakpoint
	 * @param what the "what" of the breakpoint
	 * @param pending if pending, the location that is not yet resolved
	 * @param enabled true if the breakpoint is enabled, false otherwise
	 * @param times the number of times the breakpoint has been hit
	 * @param locations the resolved address(es) of this breakpoint
	 */
	GdbBreakpointInfo(long number, GdbBreakpointType type, String typeName, GdbBreakpointDisp disp,
			String addr, String what, String catchType, String origLoc, String pending,
			boolean enabled, int times, List<GdbBreakpointLocation> locations) {
		this.number = number;
		this.type = type;
		this.typeName = typeName;
		this.disp = disp;
		this.addr = addr;
		this.what = what;
		this.catchType = catchType;
		this.originalLocation = origLoc;
		this.pending = pending;
		this.enabled = enabled;
		this.times = times;
		this.locations = Collections.unmodifiableList(locations);
	}

	@Override
	public int hashCode() {
		return Objects.hash(number, type, disp, addr, pending, enabled, times, locations);
	}

	@Override
	public String toString() {
		return String.format(
			"<%s id=%08x,number=%d,type=%s,disp=%s,addr=%s,pending=%s,enabled=%s,times=%d,locations=%s>",
			getClass().getSimpleName(), System.identityHashCode(this), number, type, disp, addr,
			pending, enabled, times, locations);
	}

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof GdbBreakpointInfo))) {
			return false;
		}
		GdbBreakpointInfo that = (GdbBreakpointInfo) obj;
		if (this.number != that.number) {
			return false;
		}
		if (this.type != that.type) {
			return false;
		}
		if (this.disp != that.disp) {
			return false;
		}
		if (!Objects.equals(this.addr, that.addr)) {
			return false;
		}
		if (!Objects.equals(this.pending, that.pending)) {
			return false;
		}
		if (this.enabled != that.enabled) {
			return false;
		}
		if (this.times != that.times) {
			return false;
		}
		if (!Objects.equals(this.locations, that.locations)) {
			return false;
		}
		return true;
	}

	/**
	 * Get the GDB-assigned breakpoint number
	 * 
	 * This is the key into GDB's breakpoint table to locate the breakpoint this information
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
	public GdbBreakpointType getType() {
		return type;
	}

	/**
	 * Get the type of breakpoint as named by GDB
	 * 
	 * <p>
	 * In case of {@link GdbBreakpointType#OTHER}, this at least reports the string GDB uses to name
	 * the type.
	 * 
	 * @return the type name
	 */
	public String getTypeName() {
		return typeName;
	}

	/**
	 * Get the breakpoint disposition, i.e., what happens to the breakpoint once it has been hit
	 * 
	 * @return the disposition
	 */
	public GdbBreakpointDisp getDisp() {
		return disp;
	}

	/**
	 * Get the location of the breakpoint
	 * 
	 * @return the location (address)
	 */
	public String getAddress() {
		return addr;
	}

	/**
	 * Get the user-specified location ("What" column)
	 * 
	 * @return the location
	 */
	public String getWhat() {
		return what;
	}

	/**
	 * For a catchpoint, get the event being caught
	 * 
	 * @return the catch-type
	 */
	public String getCatchType() {
		return catchType;
	}

	/**
	 * Get the location as specified by the user
	 * 
	 * @return the original location
	 */
	public String getOriginalLocation() {
		return originalLocation;
	}

	/**
	 * Assuming the location is an address, get it as a long
	 * 
	 * @return the address
	 */
	public long addrAsLong() {
		return GdbParsingUtils.parsePrefixedHex(addr);
	}

	/**
	 * If the breakpoint is pending resolution, get the location that is pending
	 * 
	 * @return the pending location
	 */
	public String getPending() {
		return pending;
	}

	/**
	 * Check if the breakpoint is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Get the number of times the breakpoint has been hit
	 * 
	 * @return the hit count
	 */
	public int getTimes() {
		return times;
	}

	/**
	 * Get a list of resolved addresses
	 * 
	 * The effective locations may change for a variety of reasons. Most notable, a new module may
	 * be loaded, having location(s) that match the desired location of this breakpoint. The binary
	 * addresses within will become new effective locations of this breakpoint.
	 * 
	 * @return the list of locations at the time the breakpoint information was captured
	 */
	public List<GdbBreakpointLocation> getLocations() {
		return locations;
	}

	public GdbBreakpointInfo withEnabled(@SuppressWarnings("hiding") boolean enabled) {
		if (isEnabled() == enabled) {
			return this;
		}
		return new GdbBreakpointInfo(number, type, typeName, disp, addr, what, catchType,
			originalLocation, pending, enabled, times, locations);
	}
}
