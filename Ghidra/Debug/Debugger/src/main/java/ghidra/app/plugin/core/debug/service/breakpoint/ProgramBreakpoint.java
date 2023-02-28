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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.*;

import com.google.gson.*;

import db.Transaction;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.app.services.LogicalBreakpoint.ProgramMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The static side of a mapped logical breakpoint
 * 
 * <p>
 * Programs don't have a built-in concept of breakpoints, so we store them as breakpoints with a
 * specific type for each state. We also encode other intrinsic properties (length and kinds) to the
 * category. Extrinsic properties (name and sleigh) are encoded in the comment. Because traces are
 * fairly ephemeral, the program bookmarks are the primary means a user has to save and manage a
 * breakpoint set.
 */
public class ProgramBreakpoint {
	private static final Gson GSON = new GsonBuilder().create();

	/**
	 * A class for (de)serializing breakoint properties in the bookmark's comments
	 */
	static class BreakpointProperties {
		public String name;
		public String sleigh;

		public BreakpointProperties(String name, String sleigh) {
			this.name = name;
			this.sleigh = sleigh;
		}
	}

	/**
	 * Get the kinds of a breakpoint from its bookmark
	 * 
	 * @param mark the bookmark representing a breakpoint
	 * @return the kinds
	 */
	public static Set<TraceBreakpointKind> kindsFromBookmark(Bookmark mark) {
		String[] parts = mark.getCategory().split(";");
		Set<TraceBreakpointKind> result = TraceBreakpointKindSet.decode(parts[0], false);
		if (result.isEmpty()) {
			Msg.warn(TraceBreakpointKind.class,
				"Decoded empty set of kinds from bookmark. Assuming SW_EXECUTE");
			return Set.of(TraceBreakpointKind.SW_EXECUTE);
		}
		return result;
	}

	/**
	 * Get the length of a breakpoint from its bookmark
	 * 
	 * @param mark the bookmark representing a breakpoint
	 * @return the length in bytes
	 */
	public static long lengthFromBookmark(Bookmark mark) {
		String[] parts = mark.getCategory().split(";");
		if (parts.length < 2) {
			Msg.warn(DebuggerLogicalBreakpointServicePlugin.class,
				"No length for bookmark breakpoint. Assuming 1.");
			return 1;
		}
		try {
			long length = Long.parseLong(parts[1]);
			if (length <= 0) {
				Msg.warn(DebuggerLogicalBreakpointServicePlugin.class,
					"Non-positive length for bookmark breakpoint? Using 1.");
				return 1;
			}
			return length;
		}
		catch (NumberFormatException e) {
			Msg.warn(DebuggerLogicalBreakpointServicePlugin.class,
				"Ill-formatted bookmark breakpoint length: " + e + ". Using 1.");
			return 1;
		}
	}

	private final Program program;
	private final Address address;
	private final ProgramLocation location;
	private final long length;
	private final Set<TraceBreakpointKind> kinds;

	private Bookmark eBookmark; // when present
	private Bookmark dBookmark; // when present

	private String name;
	private String sleigh;

	/**
	 * Construct a program breakpoint
	 * 
	 * @param program the program
	 * @param address the static address of the breakpoint (even if a bookmark is not present there)
	 * @param length the length of the breakpoint in bytes
	 * @param kinds the kinds of the breakpoint
	 */
	public ProgramBreakpoint(Program program, Address address, long length,
			Set<TraceBreakpointKind> kinds) {
		this.program = program;
		this.address = address;
		this.location = new ProgramLocation(program, address);
		this.length = length;
		this.kinds = kinds;
	}

	@Override
	public String toString() {
		// volatile reads
		Bookmark eBookmark = this.eBookmark;
		Bookmark dBookmark = this.dBookmark;
		if (eBookmark != null) {
			return String.format("<enabled %s(%s) at %s in %s>", eBookmark.getTypeString(),
				eBookmark.getCategory(), eBookmark.getAddress(), program.getName());
		}
		else if (dBookmark != null) {
			return String.format("<disabled %s(%s) at %s in %s>", dBookmark.getTypeString(),
				dBookmark.getCategory(), dBookmark.getAddress(), program.getName());
		}
		else {
			return String.format("<absent at %s in %s>", address, program.getName());
		}
	}

	/**
	 * Get the breakpoint's static program location
	 * 
	 * @return the location
	 */
	public ProgramLocation getLocation() {
		return location;
	}

	private void syncProperties(Bookmark bookmark) {
		if (bookmark == null) {
			name = "";
			sleigh = null;
			return;
		}
		String comment = bookmark.getComment();
		if (comment == null || !comment.startsWith("{")) {
			// Backward compatibility.
			name = comment;
			sleigh = null;
			return;
		}
		try {
			BreakpointProperties props = GSON.fromJson(comment, BreakpointProperties.class);
			name = props.name;
			sleigh = props.sleigh;
			return;
		}
		catch (JsonSyntaxException e) {
			Msg.error(this, "Could not parse breakpoint bookmark properties", e);
			name = "";
			sleigh = null;
			return;
		}
	}

	private String computeComment() {
		if ((name == null || "".equals(name)) && (sleigh == null || "".equals(sleigh))) {
			return null;
		}
		return GSON.toJson(new BreakpointProperties(name, sleigh));
	}

	private void writeProperties(Bookmark bookmark) {
		try (Transaction tx = program.openTransaction("Rename breakpoint")) {
			bookmark.set(bookmark.getCategory(), computeComment());
		}
		catch (ConcurrentModificationException e) {
			/**
			 * Can happen during breakpoint deletion. Doesn't seem like there's a good way to check.
			 * In any case, we need to keep processing events, so log and continue.
			 */
			Msg.error(this, "Could not update breakpoint properties: " + e);
		}
	}

	/**
	 * Get the user-defined name of the breakpoint
	 * 
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Set the name of the breakpoint
	 * 
	 * @param name the name
	 */
	public void setName(String name) {
		Bookmark bookmark = getBookmark();
		if (bookmark == null) {
			throw new IllegalStateException("Must save breakpoint to program before naming it");
		}
		this.name = name;
		writeProperties(bookmark);
	}

	/**
	 * Get the sleigh injection for this breakpoint
	 * 
	 * @return the sleigh injection
	 */
	public String getEmuSleigh() {
		return sleigh;
	}

	/***
	 * Set the sleigh injection for this breakpoint
	 * 
	 * @param sleigh the sleigh injection
	 */
	public void setEmuSleigh(String sleigh) {
		this.sleigh = sleigh;
		Bookmark bookmark = getBookmark();
		if (bookmark == null) {
			return;
		}
		writeProperties(bookmark);
	}

	/**
	 * Compute the mode of this breakpoint
	 * 
	 * <p>
	 * In order to ensure at least the saved state (enablement) can be rendered in the marker margin
	 * in the absence of the breakpoint marker plugin, we use one type of bookmark for disabled
	 * breakpoints, and another for enabled breakpoints. As the state is changing, it's possible for
	 * a brief moment that both bookmarks are present. We thus have a variable for each bookmark and
	 * prefer the "enabled" state. We can determine are state by examining which variable is
	 * non-null. If both are null, the breakpoint is not actually saved to the program, yet. We
	 * cannot return {@link ProgramMode#NONE}, because that would imply there is no static location.
	 * 
	 * @return the state
	 */
	public ProgramMode computeMode() {
		if (eBookmark != null) {
			return ProgramMode.ENABLED;
		}
		if (dBookmark != null) {
			return ProgramMode.DISABLED;
		}
		return ProgramMode.MISSING;
	}

	/**
	 * Check if either bookmark is present
	 * 
	 * @return true if both are absent, false if either or both is present
	 */
	public boolean isEmpty() {
		return eBookmark == null && dBookmark == null;
	}

	/**
	 * Remove the bookmark
	 * 
	 * <p>
	 * Note this does not necessarily destroy the breakpoint, since it may still exist in one or
	 * more traces.
	 */
	public void deleteFromProgram() {
		// volatile reads
		Bookmark eBookmark = this.eBookmark;
		Bookmark dBookmark = this.dBookmark;
		try (Transaction tx = program.openTransaction("Clear breakpoint")) {
			BookmarkManager bookmarkManager = program.getBookmarkManager();
			if (eBookmark != null) {
				bookmarkManager.removeBookmark(eBookmark);
			}
			if (dBookmark != null) {
				bookmarkManager.removeBookmark(dBookmark);
			}
			// (e,d)Bookmark Gets nulled on program change callback
			// If null here, logical breakpoint manager will get confused
		}
	}

	/**
	 * Check if the given bookmark can fill the static side of this breakpoint
	 * 
	 * @param candProgram the program containing the bookmark
	 * @param candBookmark the bookmark
	 * @return true if the bookmark can represent this breakpoint, false otherwise
	 */
	public boolean canMerge(Program candProgram, Bookmark candBookmark) {
		if (program != candProgram) {
			return false;
		}
		if (!address.equals(candBookmark.getAddress())) {
			return false;
		}
		if (length != lengthFromBookmark(candBookmark)) {
			return false;
		}
		if (!Objects.equals(kinds, kindsFromBookmark(candBookmark))) {
			return false;
		}
		return true;
	}

	/**
	 * Get the program where this breakpoint is located
	 * 
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Fill the static side of this breakpoint with the given bookmark
	 * 
	 * <p>
	 * The caller should first use {@link #canMerge(Program, Bookmark)} to ensure the bookmark can
	 * actually represent this breakpoint.
	 * 
	 * @param bookmark the bookmark
	 * @return true if this changed the breakpoint state
	 */
	public boolean add(Bookmark bookmark) {
		if (LogicalBreakpointInternal.BREAKPOINT_ENABLED_BOOKMARK_TYPE
				.equals(bookmark.getTypeString())) {
			if (eBookmark == bookmark) {
				return false;
			}
			eBookmark = bookmark;
			syncProperties(bookmark);
			return true;
		}
		if (LogicalBreakpointInternal.BREAKPOINT_DISABLED_BOOKMARK_TYPE
				.equals(bookmark.getTypeString())) {
			if (dBookmark == bookmark) {
				return false;
			}
			dBookmark = bookmark;
			syncProperties(bookmark);
			return true;
		}
		return false;
	}

	/**
	 * Remove a bookmark from the static side of this breakpoint
	 * 
	 * @param bookmark the bookmark
	 * @return true if this changed the breakpoint state
	 */
	public boolean remove(Bookmark bookmark) {
		if (eBookmark == bookmark) {
			eBookmark = null;
			return true;
		}
		if (dBookmark == bookmark) {
			dBookmark = null;
			return true;
		}
		return false;
	}

	/**
	 * Get the bookmark representing this breakpoint, if present
	 * 
	 * @return the bookmark or null
	 */
	public Bookmark getBookmark() {
		Bookmark eBookmark = this.eBookmark;
		if (eBookmark != null) {
			return eBookmark;
		}
		return dBookmark;
	}

	protected String getComment() {
		Bookmark bookmark = getBookmark();
		return bookmark == null ? computeComment() : bookmark.getComment();
	}

	/**
	 * Check if the bookmark represents an enabled breakpoint
	 * 
	 * @return true if enabled, false if anything else
	 */
	public boolean isEnabled() {
		return computeMode() == ProgramMode.ENABLED;
	}

	/**
	 * Check if the bookmark represents a disabled breakpoint
	 * 
	 * @return true if disabled, false if anything else
	 */
	public boolean isDisabled() {
		return computeMode() == ProgramMode.DISABLED;
	}

	/**
	 * Compute the category for a new bookmark representing this breakpoint
	 * 
	 * @return the category
	 */
	public String computeCategory() {
		return TraceBreakpointKindSet.encode(kinds) + ";" + Long.toUnsignedString(length);
	}

	/**
	 * Change the state of this breakpoint by manipulating bookmarks
	 * 
	 * <p>
	 * If the breakpoint is already in the desired state, no change is made. Otherwise, this will
	 * delete the existing bookmark, if present, and create a new bookmark whose type indicates the
	 * desired state. Thus, some event processing may need to take place before this breakpoint's
	 * state is actually updated accordingly.
	 * 
	 * @param enabled the desired state, true for {@link ProgramMode#ENABLED}, false for
	 *            {@link ProgramMode#DISABLED}.
	 * @param comment the comment to give the breakpoint, almost always from {@link #getComment()}.
	 */
	public void toggleWithComment(boolean enabled, String comment) {
		String addType =
			enabled ? LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE
					: LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE;
		String delType =
			enabled ? LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE
					: LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE;
		try (Transaction tx = program.openTransaction("Toggle breakpoint")) {
			BookmarkManager manager = program.getBookmarkManager();
			String catStr = computeCategory();
			manager.setBookmark(address, addType, catStr, comment);
			manager.removeBookmarks(new AddressSet(address), delType, catStr,
				TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Enable this breakpoint
	 * 
	 * @see #toggleWithComment(boolean, String)
	 */
	public void enable() {
		if (isEnabled()) {
			return;
		}
		toggleWithComment(true, getComment());
	}

	/**
	 * Disable this breakpoint
	 * 
	 * @see #toggleWithComment(boolean, String)
	 */
	public void disable() {
		if (isDisabled()) {
			return;
		}
		toggleWithComment(false, getComment());
	}
}
