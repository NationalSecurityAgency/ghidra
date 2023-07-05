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
package ghidra.app.plugin.core.debug.stack;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.CustomStackUnwindWarning;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A frame restored from annotations applied to the trace listing
 * 
 * <p>
 * This frame operates on {@link WatchValue}s, which are more than sufficient for most GUI elements.
 * The unwinding and display of abstract values introduced by custom emulators is yet to be
 * complete.
 * 
 * <p>
 * This class may become deprecated. It allowed the GUI to use existing analysis that had been
 * annotated in this listing. Certainly, that feature will remain, since the annotations are human
 * consumable and help make sense of the stack segment. However, when other features need stack
 * frames, they may or may not pull those frames from the listing. The trouble comes when a frame
 * has 0 length. This can happen when a function has not pushed anything to the stack. On
 * architectures without link registers, it should only happen in contingent cases, e.g., the
 * analyzer can't find an exit path from the function, and so the return address location is not
 * known. However, an invocation of a leaf function on an architecture with a link register may in
 * fact have a 0-length frame for its entire life. Ghidra does not cope well with 0-length
 * structures, and for good reason. Thus, in most cases, it is recommended to unwind, using
 * {@link StackUnwinder}, and cache frames for later re-use. That pattern may be encapsulated in a
 * centralized service later.
 * 
 * @see AnalysisUnwoundFrame#applyToListing(int, TaskMonitor)
 */
public class ListingUnwoundFrame extends AbstractUnwoundFrame<WatchValue> {

	/**
	 * Check if the given data unit conventionally represents a frame
	 * 
	 * <p>
	 * This is a simple conventional check, but it should rule out accidents. It checks that the
	 * unit's data type belongs to the {@link StackUnwinder#FRAMES_PATH} category. If the user or
	 * something else puts data types in that category, it's likely data units using those types may
	 * be mistaken for frames....
	 * 
	 * @param data the candidate frame
	 * @return true if it is likely a frame
	 */
	public static boolean isFrame(TraceData data) {
		DataType type = data.getDataType();
		return type.getCategoryPath().equals(StackUnwinder.FRAMES_PATH);
	}

	/**
	 * Get the conventional level of the frame represented by the givn data unit
	 * 
	 * <p>
	 * Technically, this violates the convention a little in that it parses the comment to determine
	 * the frame's level. One alternative is to examine the upper (or lower for positive growth)
	 * addresses for other frames, but that might require strict absence of gaps between frames.
	 * Another alternative is to encode the level into a property instead, which is more hidden from
	 * the user.
	 * 
	 * @param data the frame
	 * @return the level
	 */
	private static Integer getLevel(TraceData data) {
		// TODO: Should this go into a property instead?
		String comment = data.getComment(CodeUnit.PRE_COMMENT);
		if (comment == null) {
			return null;
		}
		String[] parts = comment.split("\\s+");
		if (parts.length == 0) {
			return null;
		}
		try {
			return Integer.parseInt(parts[0]);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private final TraceData frame;

	private final int level;
	private final Address pcVal;
	private final Function function;
	private final Address base;

	private SavedRegisterMap registerMap;

	/**
	 * Recover a frame from annotations already in the trace listing
	 * 
	 * @param tool the tool requesting interpretation of the frame, which provides context for
	 *            mapped static programs.
	 * @param coordinates the coordinates (trace, thread, snap, etc.) to examine
	 * @param frame the data unit representing the frame
	 */
	public ListingUnwoundFrame(PluginTool tool, DebuggerCoordinates coordinates, TraceData frame) {
		// NOTE: Always unwinding from frame 0
		super(tool, coordinates, DebuggerPcodeUtils.buildWatchState(tool, coordinates.frame(0)));
		if (!isFrame(frame)) {
			throw new IllegalArgumentException("frame does not appear to represent a frame");
		}
		this.frame = frame;

		this.level = loadLevel();
		this.pcVal = loadProgramCounter();
		this.function = loadFunction();
		this.base = loadBasePointer();
	}

	@Override
	public boolean isFake() {
		return false;
	}

	/**
	 * Get the data unit representing this frame
	 * 
	 * @return the data unit
	 */
	public TraceData getData() {
		return frame;
	}

	@Override
	protected Address applyBase(long offset) {
		return base.add(offset);
	}

	private int loadLevel() {
		Integer l = getLevel(frame);
		if (l == null) {
			throw new IllegalStateException("Frame has no comment indicating its level");
		}
		return l;
	}

	private Address loadProgramCounter() {
		for (Reference ref : frame.getReferenceIteratorTo()) {
			if (ref.getReferenceType() != RefType.DATA) {
				continue;
			}
			if (ref.getOperandIndex() != StackUnwinder.PC_OP_INDEX) {
				continue;
			}
			return ref.getFromAddress();
		}
		throw new UnwindException("The program counter reference is missing for the frame!");
	}

	private Function loadFunction() {
		ProgramLocation staticLoc =
			mappingService.getOpenMappedLocation(new DefaultTraceLocation(frame.getTrace(), null,
				Lifespan.at(coordinates.getSnap()), pcVal));
		if (staticLoc == null) {
			throw new UnwindException(
				"The program containing the frame's function is unavailable," +
					" or the mappings have changed.");
		}
		Function function = staticLoc.getProgram()
				.getFunctionManager()
				.getFunctionContaining(staticLoc.getAddress());
		if (function == null) {
			throw new UnwindException(
				"The function for the frame is no longer present in the mapped program.");
		}
		return function;
	}

	private Address loadBasePointer() {
		for (TraceReference ref : frame.getOperandReferences(StackUnwinder.BASE_OP_INDEX)) {
			if (ref.getReferenceType() != RefType.DATA) {
				continue;
			}
			return ref.getToAddress();
		}
		return null;
	}

	@Override
	public String getDescription() {
		return frame.getComment(CodeUnit.PRE_COMMENT);
	}

	@Override
	public int getLevel() {
		return level;
	}

	@Override
	public Address getProgramCounter() {
		return pcVal;
	}

	@Override
	public Function getFunction() {
		return function;
	}

	@Override
	public Address getBasePointer() {
		return base;
	}

	@Override
	protected Address computeAddressOfReturnAddress() {
		int numComponents = frame.getNumComponents();
		for (int i = 0; i < numComponents; i++) {
			TraceData component = frame.getComponent(i);
			if (FrameStructureBuilder.RETURN_ADDRESS_FIELD_NAME.equals(component.getFieldName())) {
				return component.getMinAddress();
			}
		}
		return null;
	}

	@Override
	public Address getReturnAddress() {
		int numComponents = frame.getNumComponents();
		for (int i = 0; i < numComponents; i++) {
			TraceData component = frame.getComponent(i);
			if (FrameStructureBuilder.RETURN_ADDRESS_FIELD_NAME.equals(component.getFieldName())) {
				Object value = component.getValue();
				if (value instanceof Address returnAddress) {
					return returnAddress;
				}
			}
		}
		return null;
	}

	@Override
	public StackUnwindWarningSet getWarnings() {
		StackUnwindWarningSet warnings = new StackUnwindWarningSet();
		for (TraceBookmark bookmark : frame.getTrace()
				.getBookmarkManager()
				.getBookmarksAt(frame.getStartSnap(), frame.getMinAddress())) {
			if (!bookmark.getTypeString().equals(BookmarkType.WARNING)) {
				continue;
			}
			String comment = bookmark.getComment();
			if (comment == null) {
				continue;
			}
			for (String line : comment.split("\n")) {
				warnings.add(new CustomStackUnwindWarning(line));
			}
		}
		return warnings;
	}

	@Override
	public Exception getError() {
		// TODO: Can this be deserialized from a bookmark?
		return null;
	}

	@Override
	protected synchronized SavedRegisterMap computeRegisterMap() {
		if (registerMap != null) {
			return registerMap;
		}
		TraceData[] innerFrames = new TraceData[level];
		for (TraceData inner : trace.getCodeManager()
				.definedData()
				.get(viewSnap, frame.getMinAddress(), false)) {
			if (inner == frame) {
				continue;
			}
			if (!isFrame(inner)) {
				break;
			}
			Integer il = getLevel(inner);
			if (il == null) {
				break;
			}
			innerFrames[il] = inner;
		}
		registerMap = new SavedRegisterMap();
		for (TraceData inner : innerFrames) {
			mapSavedRegisters(language, inner, registerMap);
		}
		return registerMap;
	}

	/**
	 * Apply the saved registers for a given frame to the given map
	 * 
	 * <p>
	 * To be used effectively, all inner frames, excluding the desired context frame, must be
	 * visited from innermost to outermost, i.e, from level 0 to level n-1. This will ensure that
	 * the nearest saved value is used for each register. If a register was never saved, then its
	 * value is presumed still in the actual register.
	 * 
	 * @param language the language defining the registers to map
	 * @param frame the data unit for the frame whose saved registers to consider
	 * @param map the map to modify with saved register information
	 */
	protected static void mapSavedRegisters(Language language, TraceData frame,
			SavedRegisterMap map) {
		int numComponents = frame.getNumComponents();
		for (int i = 0; i < numComponents; i++) {
			TraceData component = frame.getComponent(i);
			String name = component.getFieldName();
			if (!name.startsWith(FrameStructureBuilder.SAVED_REGISTER_FIELD_PREFIX)) {
				continue;
			}
			String regName =
				name.substring(FrameStructureBuilder.SAVED_REGISTER_FIELD_PREFIX.length());
			Register register = language.getRegister(regName);
			if (register == null) {
				Msg.warn(ListingUnwoundFrame.class,
					"Unknown register name in saved_register field: " + regName);
				continue;
			}
			map.put(TraceRegisterUtils.rangeForRegister(register), component.getRange());
		}
	}

	/**
	 * Get the stack entry containing the given address
	 * 
	 * @param address the address, must already have base applied
	 * @return the component, or null
	 */
	public TraceData getComponentContaining(Address address) {
		return frame.getComponentContaining((int) address.subtract(frame.getMinAddress()));
	}
}
