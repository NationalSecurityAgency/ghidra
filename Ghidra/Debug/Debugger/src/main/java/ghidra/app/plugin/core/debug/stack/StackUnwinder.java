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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValuePcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
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
 * <pre>
 * StackUnwinder unwinder = new StackUnwinder(tool, coordinates.getPlatform());
 * for (AnalysisUnwoundFrame<WatchValue> frame : unwinder.frames(coordinates.frame(0), monitor)) {
 * 	// check and/or cache the frame
 * }
 * </pre>
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

	private static WatchValuePcodeExecutorState getState(PluginTool tool,
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
	private final AddressSpace stackSpace;

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
		this.trace = platform.getTrace();

		this.pc = Objects.requireNonNull(platform.getLanguage().getProgramCounter(),
			"Platform must have a program counter");
		this.codeSpace = platform.getLanguage().getDefaultSpace();

		CompilerSpec compiler = platform.getCompilerSpec();
		this.sp = Objects.requireNonNull(compiler.getStackPointer(),
			"Platform must have a stack pointer");
		this.stackSpace = compiler.getStackBaseSpace();
	}

	/**
	 * Begin unwinding frames that can evaluate variables as {@link WatchValue}s
	 * 
	 * <p>
	 * While the returned frame is not technically "unwound," it is necessary to derive its base
	 * pointer in order to evaluate any of its variables and unwind subsequent frames. The returned
	 * frame has the {@link AnalysisUnwoundFrame#unwindNext(TaskMonitor)} method.
	 * 
	 * @param coordinates the starting coordinates, particularly the frame level
	 * @param monitor a monitor for cancellation
	 * @return the frame for the given level
	 * @throws CancelledException if the monitor is cancelled
	 */
	public AnalysisUnwoundFrame<WatchValue> start(DebuggerCoordinates coordinates,
			TaskMonitor monitor)
			throws CancelledException {
		if (coordinates.getPlatform() != platform) {
			throw new IllegalArgumentException("Not same platform");
		}
		return start(coordinates, getState(tool, coordinates), monitor);
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
	 * @param <T> the type of values in the state, and the result of variable evaluations
	 * @param coordinates the starting coordinates, particularly the frame level
	 * @param state the state, which must correspond to the given coordinates
	 * @param monitor a monitor for cancellation
	 * @return the frame for the given level
	 * @throws CancelledException if the monitor is cancelled
	 */
	public <T> AnalysisUnwoundFrame<T> start(DebuggerCoordinates coordinates,
			PcodeExecutorState<T> state, TaskMonitor monitor) throws CancelledException {
		return start(coordinates, coordinates.getFrame(), state, monitor);
	}

	protected <T> AnalysisUnwoundFrame<T> start(DebuggerCoordinates coordinates, int level,
			PcodeExecutorState<T> state, TaskMonitor monitor) throws CancelledException {
		Address pcVal = null;
		TraceThread thread = coordinates.getThread();
		long viewSnap = coordinates.getViewSnap();
		TraceStack stack = trace.getStackManager().getLatestStack(thread, viewSnap);
		if (stack != null) {
			TraceStackFrame frame = stack.getFrame(level, false);
			if (frame != null) {
				pcVal = frame.getProgramCounter(viewSnap);
			}
		}
		TraceMemorySpace regs = Objects.requireNonNull(
			trace.getMemoryManager().getMemoryRegisterSpace(thread, level, false),
			"Frame must have a register bank");
		if (pcVal == null) {
			if (TraceMemoryState.KNOWN != regs.getState(platform, viewSnap, pc)) {
				throw new UnwindException("Frame must have KNOWN " + pc + " value");
			}
			pcVal = codeSpace.getAddress(
				regs.getValue(platform, viewSnap, pc).getUnsignedValue().longValue());
		}
		if (TraceMemoryState.KNOWN != regs.getState(platform, viewSnap, sp)) {
			throw new UnwindException("Frame must have KNOWN " + sp + " value");
		}
		Address spVal = stackSpace.getAddress(
			regs.getValue(platform, viewSnap, sp).getUnsignedValue().longValue());
		return unwind(coordinates, level, pcVal, spVal, state, new SavedRegisterMap(), monitor);
	}

	record StaticAndUnwind(Address staticPc, UnwindInfo info) {
	}

	/**
	 * Compute the unwind information for the given program counter and context
	 * 
	 * <p>
	 * For the most part, this just translates the dynamic program counter to a static program
	 * address and then invokes {@link UnwindAnalysis#computeUnwindInfo(Address, TaskMonitor)}.
	 * 
	 * @param snap the snapshot key (used for mapping the program counter to a program database)
	 * @param level the frame level, used only for error messages
	 * @param pcVal the program counter (dynamic)
	 * @param monitor a monitor for cancellation
	 * @return the unwind info, possibly incomplete
	 * @throws CancelledException if the monitor is cancelled
	 */
	public StaticAndUnwind computeUnwindInfo(long snap, int level, Address pcVal,
			TaskMonitor monitor) throws CancelledException {
		// TODO: Try markup in trace first?
		ProgramLocation staticPcLoc = mappings == null ? null
				: mappings.getOpenMappedLocation(
					new DefaultTraceLocation(trace, null, Lifespan.at(snap), pcVal));
		if (staticPcLoc == null) {
			throw new UnwindException("Cannot find static program for frame " + level + " (" +
				pc + "=" + pcVal + ")");
		}
		Program program = staticPcLoc.getProgram();
		Address staticPc = staticPcLoc.getAddress();
		try {
			// TODO: Cache these?
			UnwindAnalysis ua = new UnwindAnalysis(program);
			return new StaticAndUnwind(staticPc, ua.computeUnwindInfo(staticPc, monitor));
		}
		catch (Exception e) {
			return new StaticAndUnwind(staticPc, UnwindInfo.errorOnly(e));
		}
	}

	<T> AnalysisUnwoundFrame<T> unwind(DebuggerCoordinates coordinates, int level, Address pcVal,
			Address spVal, PcodeExecutorState<T> state, SavedRegisterMap registerMap,
			TaskMonitor monitor) throws CancelledException {
		try {
			StaticAndUnwind sau = computeUnwindInfo(coordinates.getSnap(), level, pcVal, monitor);
			return new AnalysisUnwoundFrame<>(tool, coordinates, this, state, level, pcVal, spVal,
				sau.staticPc, sau.info, registerMap);
		}
		catch (Exception e) {
			return new AnalysisUnwoundFrame<>(tool, coordinates, this, state, level, pcVal, spVal,
				null, UnwindInfo.errorOnly(e), registerMap);
		}
	}

	/**
	 * An iterable wrapper for {@link #start(DebuggerCoordinates, PcodeExecutorState, TaskMonitor)}
	 * and {@link AnalysisUnwoundFrame#unwindNext(TaskMonitor)}
	 * 
	 * @param <T> the type of values in the state
	 * @param coordinates the starting coordinates
	 * @param state the state
	 * @param monitor the monitor
	 * @return the iterable over unwound frames
	 */
	public <T> Iterable<AnalysisUnwoundFrame<T>> frames(DebuggerCoordinates coordinates,
			PcodeExecutorState<T> state, TaskMonitor monitor) {
		return new Iterable<>() {
			@Override
			public Iterator<AnalysisUnwoundFrame<T>> iterator() {
				return new Iterator<>() {
					AnalysisUnwoundFrame<T> next = tryStart();

					@Override
					public boolean hasNext() {
						return next != null;
					}

					@Override
					public AnalysisUnwoundFrame<T> next() {
						AnalysisUnwoundFrame<T> cur = next;
						next = tryNext();
						return cur;
					}

					private AnalysisUnwoundFrame<T> tryStart() {
						try {
							return start(coordinates, state, monitor);
						}
						catch (UnwindException | CancelledException e) {
							return null;
						}
					}

					private AnalysisUnwoundFrame<T> tryNext() {
						try {
							return next.unwindNext(monitor);
						}
						catch (NoSuchElementException | UnwindException | CancelledException e) {
							return null;
						}
					}
				};
			}
		};
	}

	/**
	 * An iterable wrapper for {@link #start(DebuggerCoordinates, TaskMonitor)} and
	 * {@link AnalysisUnwoundFrame#unwindNext(TaskMonitor)}
	 * 
	 * @param coordinates the starting coordinates
	 * @param monitor the monitor
	 * @return the iterable over unwound frames
	 */
	public Iterable<AnalysisUnwoundFrame<WatchValue>> frames(DebuggerCoordinates coordinates,
			TaskMonitor monitor) {
		return frames(coordinates, getState(tool, coordinates), monitor);
	}
}
