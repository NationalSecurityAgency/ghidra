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

import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.bookmark.BookmarkNavigator;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.bookmark.*;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.symbol.TraceReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A frame recovered from analysis of a thread's register bank and stack segment
 * 
 * <p>
 * The typical pattern for invoking analysis to unwind an entire stack is to use
 * {@link StackUnwinder#start(DebuggerCoordinates, TaskMonitor)} or similar, followed by
 * {@link #unwindNext(TaskMonitor)} in a chain until the stack is exhausted or analysis fails to
 * unwind a frame. It may be more convenient to use
 * {@link StackUnwinder#frames(DebuggerCoordinates, TaskMonitor)}. Its iterator implements that
 * pattern. Because unwinding can be expensive, it is recommended to cache the unwound stack when
 * possible. A centralized service for stack unwinding may be added later.
 * 
 * @param <T> the type of values retrievable from the unwound frame
 */
public class AnalysisUnwoundFrame<T> extends AbstractUnwoundFrame<T> {

	private final StackUnwinder unwinder;
	private final int level;
	private final Address pcVal;
	private final Address spVal;
	private final Address staticPcVal;
	private final UnwindInfo info;
	private final SavedRegisterMap registerMap;

	private final Address base;

	/**
	 * Construct an unwound frame
	 * 
	 * <p>
	 * Clients should instead use {@link StackUnwinder#start(DebuggerCoordinates, TaskMonitor)} or
	 * similar, or {@link #unwindNext(TaskMonitor)}.
	 * 
	 * @param tool the tool requesting interpretation of the frame, which provides context for
	 *            mapped static programs.
	 * @param coordinates the coordinates (trace, thread, snap, etc.) to examine
	 * @param unwinder the unwinder that produced this frame, and may be used to unwind the next
	 *            frame
	 * @param state the machine state, typically the watch value state for the same coordinates. It
	 *            is the caller's (i.e., subclass') responsibility to ensure the given state
	 *            corresponds to the given coordinates.
	 * @param level the level of this frame
	 * @param pcVal the (dynamic) address of the next instruction when this frame becomes the
	 *            current frame
	 * @param spVal the address of the top of the stack when this frame becomes the current frame
	 * @param staticPcVal the (static) address of the next instruction
	 * @param info the information used to unwind this frame
	 * @param infoErr if applicable, an error describing why the unwind info is missing or
	 *            incomplete
	 * @param registerMap a map from registers to the offsets of their saved values on the stack
	 */
	AnalysisUnwoundFrame(PluginTool tool, DebuggerCoordinates coordinates, StackUnwinder unwinder,
			PcodeExecutorState<T> state, int level, Address pcVal, Address spVal,
			Address staticPcVal, UnwindInfo info, SavedRegisterMap registerMap) {
		super(tool, coordinates, state);
		this.unwinder = unwinder;
		this.level = level;

		this.pcVal = pcVal;
		this.spVal = spVal;
		this.staticPcVal = staticPcVal;
		this.info = info;
		this.registerMap = registerMap;

		this.base = info.computeBase(spVal);
	}

	@Override
	public boolean isFake() {
		return false;
	}

	/**
	 * Unwind the next frame up
	 * 
	 * <p>
	 * Unwind the frame that would become current if the function that allocated this frame were to
	 * return. For example, if this frame is at level 3, {@code unwindNext} will attempt to unwind
	 * the frame at level 4.
	 * 
	 * <p>
	 * The program counter and stack pointer for the next frame are computed using the state
	 * originally given in
	 * {@link StackUnwinder#start(DebuggerCoordinates, PcodeExecutorState, TaskMonitor)} and this
	 * frame's unwind information. The state is usually the watch-value state bound to the starting
	 * coordinates. The program counter is evaluated like any other variable. The stack pointer is
	 * computed by removing the depth of this frame. Then registers are restored and unwinding
	 * proceeds the same as the starting frame.
	 * 
	 * @param monitor a monitor for cancellation
	 * @return the next frame up
	 * @throws CancelledException if the monitor is cancelled
	 * @throws UnwindException if unwinding fails
	 */
	public AnalysisUnwoundFrame<T> unwindNext(TaskMonitor monitor) throws CancelledException {
		if (info == null || info.ofReturn() == null) {
			throw new NoSuchElementException();
		}
		SavedRegisterMap registerMap = this.registerMap.fork();
		info.mapSavedRegisters(base, registerMap);
		Address pcVal = info.computeNextPc(base, state, codeSpace, pc);
		Address spVal = info.computeNextSp(base);
		return unwinder.unwind(coordinates, level + 1, pcVal, spVal, state, registerMap,
			monitor);
	}

	@Override
	protected Address applyBase(long offset) {
		if (base == null) {
			throw new UnwindException(
				"Cannot compute stack address for offset %d.\nFrame error: %s".formatted(offset,
					info.error().getMessage()),
				info.error());
		}
		return base.add(offset);
	}

	@Override
	protected SavedRegisterMap computeRegisterMap() {
		return registerMap;
	}

	@Override
	protected Address computeAddressOfReturnAddress() {
		return info.ofReturn(base);
	}

	@Override
	public Address getReturnAddress() {
		return info.computeNextPc(base, state, codeSpace, pc);
	}

	@Override
	public CompletableFuture<Void> setReturnAddress(StateEditor editor, Address addr) {
		if (addr.getAddressSpace() != codeSpace) {
			throw new IllegalArgumentException("Return address must be in " + codeSpace);
		}
		BytesPcodeArithmetic bytesArithmetic = BytesPcodeArithmetic.forLanguage(language);
		byte[] bytes = bytesArithmetic.fromConst(addr.getOffset(), pc.getNumBytes());
		return editor.setVariable(info.ofReturn(base), bytes);
	}

	@Override
	public int getLevel() {
		return level;
	}

	@Override
	public String getDescription() {
		return String.format("%s %s pc=%s sp=%s base=%s",
			level, info.function(),
			pcVal == null ? null : pcVal.toString(false),
			spVal == null ? null : spVal.toString(false),
			base == null ? null : base.toString(false));
	}

	@Override
	public Address getBasePointer() {
		return base;
	}

	@Override
	public Address getProgramCounter() {
		return pcVal;
	}

	public Address getStackPointer() {
		return spVal;
	}

	@Override
	public Function getFunction() {
		return info.function();
	}

	/**
	 * Generate the structure for {@link #resolveStructure(int)}
	 * 
	 * @param prevParamSize the number of bytes occupied by the parameters for the next frame down.
	 * @return the generated structure
	 */
	protected Structure generateStructure(int prevParamSize) {
		FrameStructureBuilder builder =
			new FrameStructureBuilder(language, staticPcVal, info, prevParamSize);
		return builder.build(StackUnwinder.FRAMES_PATH, "frame_" + pcVal.toString(false),
			trace.getDataTypeManager());
	}

	/**
	 * Create or resolve the structure data type representing this frame
	 * 
	 * <p>
	 * The structure composes a variety of information: 1) The stack variables (locals and
	 * parameters) of the function that allocated the frame. Note that some variables may be omitted
	 * if the function has not allocated them or has already freed them relative to the frame's
	 * program counter. 2) Saved registers. Callee-saved registers will typically appear closer to
	 * the next frame up. Caller-saved registers, assuming Ghidra hasn't already assigned the stack
	 * offset to a local variable, will typically appear close to the next frame down. 3) The return
	 * address, if on the stack.
	 * 
	 * @param prevParamSize the number of bytes occupied by the parameters for the next frame down.
	 *            Parameters are pushed by the caller, and so appear to be allocated by the caller;
	 *            however, the really belong to the callee, so this specifies the number of bytes to
	 *            "donate" to the callee's frame.
	 * @return the structure, to be placed {@code prevParamSize} bytes after the frame's stack
	 *         pointer.
	 */
	public Structure resolveStructure(int prevParamSize) {
		Structure structure = generateStructure(prevParamSize);
		return structure == null ? null
				: trace.getDataTypeManager()
						.addType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	/**
	 * Get or create the bookmark type for warnings
	 * 
	 * @return the bookmark type
	 */
	protected TraceBookmarkType getWarningBookmarkType() {
		TraceBookmarkType type = trace.getBookmarkManager().getBookmarkType(BookmarkType.WARNING);
		if (type != null) {
			return type;
		}
		BookmarkNavigator.defineBookmarkTypes(trace.getProgramView());
		return trace.getBookmarkManager().getBookmarkType(BookmarkType.WARNING);
	}

	protected static void truncateOrDelete(TraceBookmark tb, Lifespan remove) {
		List<Lifespan> newLifespan = tb.getLifespan().subtract(remove);
		if (newLifespan.isEmpty()) {
			tb.delete();
		}
		else {
			tb.setLifespan(newLifespan.get(0));
		}
	}

	/**
	 * Apply this unwound frame to the trace's listing
	 * 
	 * <p>
	 * This performs the following, establishing some conventions for trace stack analysis:
	 * <ul>
	 * <li>Places a bookmark at the frame start indicating any warnings encountered while analyzing
	 * it.</li>
	 * <li>Places a structure at (or near) the derived stack pointer whose fields denote the various
	 * stack entries: local variables, saved registers, return address, parameters. The structure
	 * may be placed a little after the derived stack pointer to accommodate the parameters of an
	 * inner stack frame. The structure data type will have the category path
	 * {@link StackUnwinder#FRAMES_PATH}. This allows follow-on analysis to identify data units
	 * representing unwound frames. See {@link #isFrame(TraceData)}.</li>
	 * <li>Places a comment at the start of the frame. This is meant for human consumption, so
	 * follow-on analysis should not attempt to parse or otherwise interpret it. It will indicate
	 * the frame level (0 being the innermost), the function name, the program counter, the stack
	 * pointer, and the frame base pointer.</li>
	 * <li>Places a {@link RefType#DATA} reference from the frame start to its own base address.
	 * This permits follow-on analysis to derive variable values stored on the stack. See
	 * {@link #getBase(TraceData)} and {@link #getValue(TraceData, VariableStorage)}.</li>
	 * <li>Places a {@link RefType#DATA} reference from the program counter to the frame start. This
	 * allows follow-on analysis to determine the function for the frame. See
	 * {@link #getProgramCounter(TraceData)} and
	 * {@link #getFunction(TraceData, DebuggerStaticMappingService)}.</li>
	 * </ul>
	 * 
	 * <p>
	 * The resulting data unit can be retrieved from the trace database and later used to construct
	 * a {@link ListingUnwoundFrame}. If the frame structure would have length 0 it is not applied.
	 * 
	 * @param prevParamSize the number of bytes occupied by the parameters for the next frame down.
	 *            See {@link #resolveStructure(int)}.
	 * @param monitor a monitor for cancellation
	 * @return the data unit for the frame structure applied, or null
	 * @throws CancelledException if the monitor is cancelled
	 */
	public TraceData applyToListing(int prevParamSize, TaskMonitor monitor)
			throws CancelledException {
		// TODO: Positive stack growth
		Address spPlusParams = spVal.add(prevParamSize);
		TraceBookmarkManager bm = trace.getBookmarkManager();
		TraceBookmarkType btWarn = getWarningBookmarkType();
		Lifespan span = Lifespan.nowOnMaybeScratch(viewSnap);
		String warnings = info.warnings().summarize().stream().collect(Collectors.joining("\n"));
		Structure structure = resolveStructure(prevParamSize);
		if (structure == null || structure.isZeroLength()) {
			for (TraceBookmark existing : bm.getBookmarksAt(viewSnap, spPlusParams)) {
				truncateOrDelete(existing, span);
			}
			bm.addBookmark(span, spPlusParams, btWarn, "Stack Unwind",
				"Frame " + level + " has lenght 0");
			return null;
		}
		for (TraceBookmark existing : bm.getBookmarksIntersecting(span,
			new AddressRangeImpl(spPlusParams, spPlusParams.add(structure.getLength() - 1)))) {
			truncateOrDelete(existing, span);
		}
		if (!warnings.isBlank()) {
			bm.addBookmark(span, spPlusParams, btWarn, "Unwind Stack", warnings);
		}

		try {
			trace.getCodeManager()
					.definedUnits()
					.clear(Lifespan.at(viewSnap), new AddressRangeImpl(spPlusParams,
						spPlusParams.add(structure.getLength() - 1)), false, monitor);
			TraceData frame = trace.getCodeManager()
					.definedData()
					.create(span, spPlusParams, structure);
			frame.setComment(CodeUnit.PRE_COMMENT, getDescription());
			TraceReferenceManager refs = trace.getReferenceManager();
			refs.clearReferencesFrom(span, frame.getRange());
			refs.clearReferencesTo(span, frame.getRange());
			frame.addOperandReference(StackUnwinder.BASE_OP_INDEX, base, RefType.DATA,
				SourceType.ANALYSIS);
			refs.addMemoryReference(span, pcVal, spPlusParams, RefType.DATA, SourceType.ANALYSIS,
				StackUnwinder.PC_OP_INDEX);
			return frame;
		}
		catch (CodeUnitInsertionException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Get the unwind information from the analysis used to unwind this frame
	 * 
	 * @return the information
	 */
	public UnwindInfo getUnwindInfo() {
		return info;
	}

	@Override
	public StackUnwindWarningSet getWarnings() {
		return info.warnings();
	}

	@Override
	public Exception getError() {
		return info.error();
	}
}
