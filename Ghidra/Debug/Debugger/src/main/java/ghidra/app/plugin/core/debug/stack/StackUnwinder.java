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

import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueHoverService;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.CustomStackUnwindWarning;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValuePcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A mechanism for unwinding the stack or parts of it
 * 
 * <p>
 * It can start at any frame for which the program counter and stack pointer are known. The choice
 * of starting frame is informed by some tradeoffs. For making sense of a specific frame, it might
 * be best to start at the nearest frame with confidently recorded PC and SP values. This will
 * ensure there is little room for error unwinding from the known frame to the desired frame. For
 * retrieving variable values, esp. variables stored in registers, it might be best to start at the
 * innermost frame, unless all registers in a nearer frame are confidently recorded. The registers
 * in frame 0 are typically recorded with highest confidence. This will ensure that all saved
 * register values are properly restored from the stack into the desired frame.
 * 
 * <p>
 * The usage pattern is typically:
 * 
 * <pre>{@code
 * StackUnwinder unwinder = new StackUnwinder(tool, coordinates.getPlatform());
 * for (AnalysisUnwoundFrame<WatchValue> frame : unwinder.frames(coordinates.frame(0), monitor)) {
 * 	// check and/or cache the frame
 * }
 * }</pre>
 * 
 * <p>
 * Typically, a frame is sought either by its level or by its function. Once found, several
 * operations can be performed with it, including applying annotations to the listing for the stack
 * segment (see {@link AnalysisUnwoundFrame#applyToListing(int, TaskMonitor)}) and computing values
 * of variables (see {@link UnwoundFrame}.) The iterator unwinds each frame lazily. If the iterator
 * stops sooner than expected, consider using {@link #start(DebuggerCoordinates, TaskMonitor)} and
 * {@link AnalysisUnwoundFrame#unwindNext(TaskMonitor)} directly to get better diagnostics.
 */
public class StackUnwinder {
	public static final CategoryPath FRAMES_PATH = new CategoryPath("/Frames");
	public static final int PC_OP_INDEX = Reference.MNEMONIC;
	public static final int BASE_OP_INDEX = 0;

	private static DebuggerStaticMappingService getMappings(PluginTool tool) {
		return tool.getService(DebuggerStaticMappingService.class);
	}

	public static WatchValuePcodeExecutorState getState(PluginTool tool,
			DebuggerCoordinates coordinates) {
		return DebuggerPcodeUtils.buildWatchState(tool, coordinates);
	}

	private final PluginTool tool;
	private final DebuggerStaticMappingService mappings;
	final TracePlatform platform;
	final Trace trace;

	final Register pc;
	final AddressSpace codeSpace;
	private final Register sp;

	record ThreadAndSnap(TraceThread thread, Long viewSnap) {}

	private Map<ThreadAndSnap, TreeMap<Integer, AnalysisUnwoundFrame<WatchValue>>> unwound =
		new HashMap<>();
	private boolean returnErrorFrame = false;
	private VariableValueHoverService service;

	/**
	 * Construct an unwinder
	 * 
	 * @param tool the tool with applicable modules opened as programs
	 * @param platform the trace platform (for registers, spaces, and stack conventions)
	 */
	public StackUnwinder(PluginTool tool, TracePlatform platform) {
		this.tool = tool;
		this.mappings = getMappings(tool);
		this.platform = platform;
		this.service = tool.getService(VariableValueHoverService.class);
		this.trace = platform.getTrace();

		this.pc = Objects.requireNonNull(platform.getLanguage().getProgramCounter(),
			"Platform must have a program counter");
		this.codeSpace = platform.getLanguage().getDefaultSpace();

		CompilerSpec compiler = platform.getCompilerSpec();
		this.sp = Objects.requireNonNull(compiler.getStackPointer(),
			"Platform must have a stack pointer");
	}

	/**
	 * Begin unwinding frames that can evaluate variables from the given state
	 * 
	 * <p>
	 * If is the caller's responsibility to ensure that the given state corresponds to the given
	 * coordinates. If they do not, the result is undefined.
	 * 
	 * <p>
	 * The starting frame's program counter and stack pointer are derived from the trace (in
	 * coordinates), not the state. The program counter will be retrieved from the
	 * {@link TraceStackFrame} if available. Otherwise, it will use the value in the register bank
	 * for the starting frame level. If it is not known, the unwind fails. The static (module)
	 * mappings are used to find the function containing the program counter, and that function is
	 * analyzed for its unwind info, wrt. the mapped program counter. See
	 * {@link UnwindAnalysis#computeUnwindInfo(Address, TaskMonitor)}. Depending on the complexity
	 * of the function, that analysis may be expensive. If the function cannot be found, the unwind
	 * fails. If analysis fails, the resulting frame may be incomplete, or the unwind may fail.
	 * Subsequent frames are handled similarly. See
	 * {@link AnalysisUnwoundFrame#unwindNext(TaskMonitor)}.
	 * 
	 * @param coordinates the starting coordinates, particularly the frame level
	 * @param monitor a monitor for cancellation
	 * @return the frame for the given level
	 * @throws CancelledException if the monitor is cancelled
	 */
	public AnalysisUnwoundFrame<WatchValue> start(DebuggerCoordinates coordinates,
			TaskMonitor monitor) throws CancelledException {
		if (coordinates.getPlatform() != platform) {
			throw new IllegalArgumentException("Not same platform");
		}
		returnErrorFrame = true;
		return getFrame(coordinates, getState(tool, coordinates), coordinates.getFrame(), null,
			monitor);
	}

	public AnalysisUnwoundFrame<WatchValue> getFrame(DebuggerCoordinates coordinates,
			PcodeExecutorState<?> state, int level, StackUnwindWarningSet warnings,
			TaskMonitor monitor) {
		// Current strategy: save the UnwindInfo, do not save the UnwoundFrame's.
		return unwindStack(coordinates, level, warnings, monitor);
	}

	private AnalysisUnwoundFrame<WatchValue> unwindStack(DebuggerCoordinates coordinates,
			int targetLevel, StackUnwindWarningSet warnings, TaskMonitor monitor) {
		WatchValuePcodeExecutorState state = null;
		SavedRegisterMap registerMap = null;
		AnalysisUnwoundFrame<WatchValue> frame = null;

		for (int level = coordinates.getFrame(); level <= targetLevel || targetLevel < 0; level++) {
			DebuggerCoordinates coord = coordinates.frame(level);
			if (frame == null || frame.getError() != null) {
				state = getState(tool, coord);
				registerMap = new SavedRegisterMap();
				frame = null;
			}

			ThreadAndSnap tas = new ThreadAndSnap(coord.getThread(), coord.getViewSnap());
			TreeMap<Integer, AnalysisUnwoundFrame<WatchValue>> treeMap = unwound.computeIfAbsent(
				tas, t -> new TreeMap<Integer, AnalysisUnwoundFrame<WatchValue>>());
			AnalysisUnwoundFrame<WatchValue> savedFrame = treeMap.get(coord.getFrame());
			if (savedFrame != null) {
				// Short circuit here if possible to avoid recomputing UnwindInfo
				frame = savedFrame;
				registerMap = frame.registerMap;
				continue;
			}

			Address pcVal = pcOrSp(frame, coord, warnings, state, true);
			if (pcVal == null) {
				// True if not frame 0 and no access to regs or stack
				break;
			}

			ProgramLocation loc = getProgramLocation(coord.getSnap(), pcVal);
			if (loc != null && service != null) {
				// Created UnwindInfo if it doesn't exist
				service.getUnwindInfo(loc.getProgram(), loc.getAddress(), monitor);
			}

			Address spVal = pcOrSp(frame, coord, warnings, state, false);

			SavedRegisterMap nextRegisterMap = updateMap(frame, registerMap);
			frame = unwind(coord, pcVal, spVal, state, nextRegisterMap, monitor);
			if (frame != null) {
				registerMap = frame.registerMap;
				treeMap.put(coord.getFrame(), frame);
			}
			else if (targetLevel < 0) {
				break;
			}
		}
		return frame;
	}

	private SavedRegisterMap updateMap(AnalysisUnwoundFrame<WatchValue> frame,
			SavedRegisterMap registerMap) {
		if (frame != null) {
			SavedRegisterMap nextRegisterMap = registerMap.fork();
			Address base = frame.getBasePointer();
			if (base != null) {
				frame.getUnwindInfo().mapSavedRegisters(base, nextRegisterMap);
			}
			return nextRegisterMap;
		}
		return registerMap;
	}

	private Address pcOrSp(AnalysisUnwoundFrame<WatchValue> frame,
			DebuggerCoordinates coordinates, StackUnwindWarningSet warnings,
			PcodeExecutorState<?> state, boolean getPc) {
		TraceThread thread = coordinates.getThread();
		int level = coordinates.getFrame();
		long viewSnap = coordinates.getViewSnap();

		Address regVal = null;

		// Try asking the stack
		TraceStack stack =
			trace.getStackManager().getStack(thread, viewSnap, false);
		if (stack != null) {
			TraceStackFrame frameForLevel = stack.getFrame(viewSnap, level, false);
			if (frameForLevel != null) {
				regVal = getPc ? frameForLevel.getProgramCounter(viewSnap)
						: frameForLevel.getStackPointer(viewSnap);
				if (regVal != null) {
					return regVal;
				}
			}
		}

		// Try asking the registers
		TraceMemorySpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, level, false);
		if (regs != null) {
			if (TraceMemoryState.KNOWN == regs.getState(platform, viewSnap, getPc ? pc : sp)) {
				regVal = codeSpace.getAddress(regs.getValue(platform, viewSnap, getPc ? pc : sp)
						.getUnsignedValue()
						.longValue());
				if (regVal != null) {
					return regVal;
				}
			}
		}

		// Try unwinding the stack
		if (frame != null) {
			UnwindInfo prevInfo = frame.getUnwindInfo();
			Address base = frame.getBasePointer();
			try {
				if (prevInfo.ofReturn() == null) {
					warnings.add(new CustomStackUnwindWarning(
						"Indeterminate return from frame preceding " + level));
				}
				else {
					regVal = getPc ? prevInfo.computeNextPc(base, state, codeSpace, pc)
							: prevInfo.computeNextSp(base);
					if (regVal != null) {
						return regVal;
					}
				}
			}
			catch (Exception e) {
				warnings.add(new CustomStackUnwindWarning(e.getMessage()));
			}
		}

		// Fall-back to current frame
		if (coordinates.getFrame() == 0) {
			RegisterValue rval = state.inspectRegisterValue(getPc ? pc : sp);
			return codeSpace.getAddress(rval.getUnsignedValue().longValue());
		}

		return null;
	}

	record StaticAndUnwind(Address staticPc, UnwindInfo info) {}

	/**
	 * Compute the unwind information for the given program counter and context
	 * 
	 * <p>
	 * For the most part, this just translates the dynamic program counter to a static program
	 * address and then invokes {@link UnwindAnalysis#computeUnwindInfo(Address, TaskMonitor)}.
	 * 
	 * @param snap the snapshot key (used for mapping the program counter to a program database)
	 * @param pcVal the program counter (dynamic)
	 * @param monitor a monitor for cancellation
	 * @return the unwind info, possibly incomplete
	 * @throws CancelledException if the monitor is cancelled
	 */
	public StaticAndUnwind computeUnwindInfo(long snap, Address pcVal,
			TaskMonitor monitor) throws CancelledException {
		// TODO: Try markup in trace first?
		ProgramLocation staticPcLoc = getProgramLocation(snap, pcVal);
		if (staticPcLoc == null) {
			throw new UnwindException(
				"Cannot find static program for frame  (" + pc + "=" + pcVal + ")");
		}
		Program program = staticPcLoc.getProgram();
		Address staticPc = staticPcLoc.getAddress();
		try {
			UnwindInfo info = service.getUnwindInfo(program, staticPc, monitor);
			StaticAndUnwind sau = new StaticAndUnwind(staticPc, info);
			if (sau.info().ofReturn() == null) {
				Function function = sau.info().function();
				if (function != null) {
					Address ep = function.getEntryPoint();
					UnwindInfo epInfo = service.getUnwindInfo(program, ep, monitor);
					info = new UnwindInfo(info.function(), info.depth(),
						info.adjust(), epInfo.ofReturn(), epInfo.maskOfReturn(), info.saved(),
						info.warnings(), info.error());
					sau = new StaticAndUnwind(staticPc, info);
				}
			}
			return sau;
		}
		catch (Exception e) {
			return new StaticAndUnwind(staticPc, UnwindInfo.errorOnly(e));
		}
	}

	private ProgramLocation getProgramLocation(long snap, Address pcVal) {
		return mappings == null ? null
				: mappings.getOpenMappedLocation(
					new DefaultTraceLocation(trace, null, Lifespan.at(snap), pcVal));
	}

	<T> AnalysisUnwoundFrame<T> unwind(DebuggerCoordinates coordinates, Address pcVal,
			Address spVal, PcodeExecutorState<T> state, SavedRegisterMap registerMap,
			TaskMonitor monitor) {
		try {
			StaticAndUnwind sau = computeUnwindInfo(coordinates.getSnap(), pcVal, monitor);
			return new AnalysisUnwoundFrame<>(tool, coordinates, this, state, pcVal, spVal,
				sau.staticPc, sau.info, registerMap);
		}
		catch (Exception e) {
			if (!returnErrorFrame) {
				return null;
			}
			return new AnalysisUnwoundFrame<>(tool, coordinates, this, state, pcVal, spVal, null,
				UnwindInfo.errorOnly(e), registerMap);
		}
	}

	/**
	 * A convenience method 
	 * @return the deepest level
	 */
	public int getRecoveredFrameCount() {
		return unwound.size();
	}

	public void invalidateCache() {
		unwound.clear();
	}

	public Map<Integer, AnalysisUnwoundFrame<WatchValue>> getFrames(
			DebuggerCoordinates coordinates, TaskMonitor monitor) {
		unwindStack(coordinates, getTargetReportedMaxFrame(coordinates), null, monitor);
		ThreadAndSnap tas = new ThreadAndSnap(coordinates.getThread(), coordinates.getViewSnap());
		return unwound.get(tas);
	}

	public AnalysisUnwoundFrame<WatchValue> findMatchForFunction(Function function,
			DebuggerCoordinates coordinates, StackUnwindWarningSet warnings, TaskMonitor monitor) {
		unwindStack(coordinates, getTargetReportedMaxFrame(coordinates), warnings, monitor);
		AnalysisUnwoundFrame<WatchValue> candidate = null;
		ThreadAndSnap tas = new ThreadAndSnap(coordinates.getThread(), coordinates.getViewSnap());
		for (Entry<Integer, AnalysisUnwoundFrame<WatchValue>> entry : unwound.get(tas).entrySet()) {
			AnalysisUnwoundFrame<WatchValue> frame = entry.getValue();
			if (frame.getFunction() == function) {
				StackUnwindWarningSet unwindWarnings = frame.getWarnings();
				if (unwindWarnings != null) {
					warnings.addAll(unwindWarnings);
				}
				candidate = frame;
				if (entry.getKey() >= coordinates.getFrame()) {
					return frame;
				}
			}
		}
		return candidate;
	}

	private int getTargetReportedMaxFrame(DebuggerCoordinates coordinates) {
		TraceThread thread = coordinates.getThread();
		long snap = coordinates.getViewSnap();
		TraceStack stack = trace.getStackManager().getStack(thread, snap, false);
		return stack == null ? -1 : stack.getDepth(snap) - 1;
	}
}
