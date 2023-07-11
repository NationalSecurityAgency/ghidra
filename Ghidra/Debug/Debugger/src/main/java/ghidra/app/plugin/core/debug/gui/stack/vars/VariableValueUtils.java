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
package ghidra.app.plugin.core.debug.gui.stack.vars;

import java.util.*;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.stack.*;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.CustomStackUnwindWarning;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.eval.AbstractVarnodeEvaluator;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValuePcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.*;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Various utilities for evaluating statically-defined variables in the context of a dynamic trace.
 */
public enum VariableValueUtils {
	;

	/**
	 * An "evaluator" which simply determines whether actual evaluation will require a frame for
	 * context
	 */
	private static final class RequiresFrameEvaluator extends AbstractVarnodeEvaluator<Boolean> {
		private final AddressSetView symbolStorage;

		private RequiresFrameEvaluator(AddressSetView symbolStorage) {
			this.symbolStorage = symbolStorage;
		}

		@Override
		protected boolean isLeaf(Varnode vn) {
			if (vn.getDef() == null && (vn.isRegister() || vn.isAddress())) {
				return true;
			}
			return vn.isConstant() ||
				symbolStorage.contains(vn.getAddress(), vn.getAddress().add(vn.getSize() - 1));
		}

		@Override
		protected Address applyBase(long offset) {
			throw new AssertionError();
		}

		@Override
		protected Boolean evaluateConstant(long value, int size) {
			return false;
		}

		@Override
		protected Boolean evaluateRegister(Address address, int size) {
			return true;
		}

		@Override
		protected Boolean evaluateStack(long offset, int size) {
			return true;
		}

		@Override
		protected Boolean evaluateMemory(Address address, int size) {
			return false;
		}

		@Override
		protected Boolean evaluateUnique(long offset, int size) {
			/**
			 * Generally speaking, this getting called is bad. We'll "let it go" here and the error
			 * should surface in actual evaluation.
			 */
			return false;
		}

		@Override
		protected Boolean evaluateAbstract(Program program, AddressSpace space, Boolean offset,
				int size, Map<Varnode, Boolean> already) {
			/**
			 * This generally happens for dereferences. The evaluator will already have determined
			 * if computing the address requires a frame, which we should just echo back. Neither
			 * the location of the target nor its value has any bearing on whether or not a frame is
			 * required.
			 */
			return offset;
		}

		@Override
		protected Boolean evaluateUnaryOp(Program program, PcodeOp op, UnaryOpBehavior unOp,
				Map<Varnode, Boolean> already) {
			return evaluateVarnode(program, op.getInput(0), already);
		}

		@Override
		protected Boolean evaluateBinaryOp(Program program, PcodeOp op, BinaryOpBehavior binOp,
				Map<Varnode, Boolean> already) {
			return evaluateVarnode(program, op.getInput(0), already) ||
				evaluateVarnode(program, op.getInput(1), already);
		}

		@Override
		protected Boolean evaluateLoad(Program program, PcodeOp op,
				Map<Varnode, Boolean> already) {
			return evaluateVarnode(program, op.getInput(1), already);
		}

		@Override
		protected Boolean evaluatePtrAdd(Program program, PcodeOp op,
				Map<Varnode, Boolean> already) {
			// Third input is a constant, according to pcoderef.xml
			return evaluateBinaryOp(program, op, null, already);
		}

		@Override
		protected Boolean evaluatePtrSub(Program program, PcodeOp op,
				Map<Varnode, Boolean> already) {
			return evaluateBinaryOp(program, op, null, already);
		}

		@Override
		protected Boolean catenate(int total, Boolean value, Boolean piece, int size) {
			return value || piece;
		}

		@Override
		public Boolean evaluateStorage(Program program, VariableStorage storage) {
			return evaluateStorage(program, storage, false);
		}
	}

	/**
	 * A settings that provides the given space as the default for pointers
	 */
	static class DefaultSpaceSettings implements Settings {
		final Settings delegate;
		final AddressSpace space;

		public DefaultSpaceSettings(Settings delegate, AddressSpace space) {
			this.delegate = delegate;
			this.space = space;
		}

		@Override
		public boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
			return delegate.isChangeAllowed(settingsDefinition);
		}

		@Override
		public Long getLong(String name) {
			return delegate.getLong(name);
		}

		@Override
		public String getString(String name) {
			if (AddressSpaceSettingsDefinition.DEF.getStorageKey().equals(name)) {
				return space.getName();
			}
			return delegate.getString(name);
		}

		@Override
		public Object getValue(String name) {
			if (AddressSpaceSettingsDefinition.DEF.getStorageKey().equals(name)) {
				return space.getName();
			}
			return delegate.getValue(name);
		}

		@Override
		public void setLong(String name, long value) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setString(String name, String value) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setValue(String name, Object value) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clearSetting(String name) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clearAllSettings() {
			throw new UnsupportedOperationException();
		}

		@Override
		public String[] getNames() {
			return delegate.getNames();
		}

		@Override
		public boolean isEmpty() {
			return delegate.isEmpty();
		}

		@Override
		public Settings getDefaultSettings() {
			return delegate.getDefaultSettings();
		}
	}

	/**
	 * Compute the address range where annotated frames would be expected in the listing
	 * 
	 * @param coordinates the coordinates
	 * @return the range, usually from stack pointer to the end of the stack segment
	 */
	public static AddressRange computeFrameSearchRange(DebuggerCoordinates coordinates) {
		TraceThread thread = coordinates.getThread();
		if (thread == null) {
			return null;
		}
		Trace trace = thread.getTrace();
		long viewSnap = coordinates.getViewSnap();
		TraceMemoryManager mem = trace.getMemoryManager();
		TracePlatform platform = coordinates.getPlatform();
		CompilerSpec cSpec = platform.getCompilerSpec();
		Register sp = cSpec.getStackPointer();

		TraceMemorySpace regs = mem.getMemoryRegisterSpace(thread, 0, false);
		RegisterValue spRV = regs.getValue(platform, viewSnap, sp);
		Address spVal = cSpec.getStackBaseSpace().getAddress(spRV.getUnsignedValue().longValue());
		Address max;
		TraceMemoryRegion stackRegion = mem.getRegionContaining(coordinates.getSnap(), spVal);
		if (stackRegion != null) {
			max = stackRegion.getMaxAddress();
		}
		else {
			long toMax = spVal.getAddressSpace().getMaxAddress().subtract(spVal);
			max = spVal.add(MathUtilities.unsignedMin(4095, toMax));
		}
		return new AddressRangeImpl(spVal, max);
	}

	/**
	 * Find the innermost frame for the given coordinates
	 * 
	 * @param tool the tool
	 * @param coordinates the coordinates
	 * @return the frame, or null
	 */
	public static ListingUnwoundFrame locateInnermost(PluginTool tool,
			DebuggerCoordinates coordinates) {
		AddressRange range = computeFrameSearchRange(coordinates);
		if (range == null) {
			return null;
		}
		// TODO: Positive stack growth?
		for (TraceData data : coordinates.getTrace()
				.getCodeManager()
				.definedData()
				.get(coordinates.getViewSnap(), range, true)) {
			try {
				return new ListingUnwoundFrame(tool, coordinates, data);
			}
			catch (UnwindException e) {
				Msg.warn(VariableValueUtils.class, "Skipping frame " + data + ". " + e);
				// Just try the next
			}
		}
		return null;
	}

	/**
	 * Locate an already unwound frame in the listing at the given coordinates
	 * 
	 * @param tool the tool for context, especially for mappings to static programs
	 * @param coordinates the coordinates to search. Note that recursive calls are distinguished by
	 *            the coordinates' frame level, though unwinding starts at frame 0.
	 * @param function the function the allocated the desired frame / call record
	 * @see AnalysisUnwoundFrame#applyToListing(int, TaskMonitor)
	 * @return the frame or null
	 */
	public static ListingUnwoundFrame locateFrame(PluginTool tool, DebuggerCoordinates coordinates,
			Function function) {
		int minLevel = coordinates.getFrame();
		AddressRange range = computeFrameSearchRange(coordinates);
		if (range == null) {
			return null;
		}

		// TODO: Positive stack growth?
		for (TraceData data : coordinates.getTrace()
				.getCodeManager()
				.definedData()
				.get(coordinates.getViewSnap(), range, true)) {
			try {
				ListingUnwoundFrame frame = new ListingUnwoundFrame(tool, coordinates, data);
				minLevel--;
				if (minLevel < 0 && frame.getFunction() == function) {
					return frame;
				}
			}
			catch (UnwindException e) {
				Msg.warn(VariableValueUtils.class, "Skipping frame " + data + ". " + e);
				// Just try the next
			}
		}
		Msg.info(VariableValueUtils.class, "Cannot find frame for function " + function);
		return null;
	}

	/**
	 * Check if evaluation of the given storage will require a frame
	 * 
	 * @param program the program containing the variable storage
	 * @param storage the storage to evaluate
	 * @param symbolStorage the leaves of evaluation, usually storage used by symbols in scope. See
	 *            {@link #collectSymbolStorage(ClangLine)}
	 * @return true if a frame is required, false otherwise
	 */
	public static boolean requiresFrame(Program program, VariableStorage storage,
			AddressSetView symbolStorage) {
		return new RequiresFrameEvaluator(symbolStorage).evaluateStorage(program, storage);
	}

	/**
	 * Check if evaluation of the given p-code op will require a frame
	 * 
	 * @param op the op whose output to evaluation
	 * @param symbolStorage the leaves of evaluation, usually storage used by symbols in scope. See
	 *            {@link #collectSymbolStorage(ClangLine)}
	 * @return true if a frame is required, false otherwise
	 */
	public static boolean requiresFrame(PcodeOp op, AddressSetView symbolStorage) {
		return new RequiresFrameEvaluator(symbolStorage).evaluateOp(null, op);
	}

	/**
	 * Get the program counter for the given thread's innermost frame using its {@link TraceStack}
	 * 
	 * <p>
	 * This will prefer the program counter in the {@link TraceStackFrame}. If that's not available,
	 * it will use the value of the program counter register from the thread's register bank for
	 * frame 0.
	 * 
	 * @param platform the platform
	 * @param thread the thread
	 * @param snap the snapshot key
	 * @return the address
	 */
	public static Address getProgramCounterFromStack(TracePlatform platform, TraceThread thread,
			long snap) {
		TraceStack stack = thread.getTrace().getStackManager().getStack(thread, snap, false);
		if (stack == null) {
			return null;
		}
		TraceStackFrame frame = stack.getFrame(0, false);
		if (frame == null) {
			return null;
		}
		return frame.getProgramCounter(snap);
	}

	/**
	 * Get the program counter for the given thread's innermost frame using its
	 * {@link TraceMemorySpace}, i.e., registers
	 * 
	 * @param platform the platform
	 * @param thread the thread
	 * @param snap the snapshot key
	 * @return the address
	 */
	public static Address getProgramCounterFromRegisters(TracePlatform platform, TraceThread thread,
			long snap) {
		TraceMemorySpace regs =
			thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, false);
		if (regs == null) {
			return null;
		}
		RegisterValue value =
			regs.getValue(platform, snap, platform.getLanguage().getProgramCounter());
		return platform.getLanguage()
				.getDefaultSpace()
				.getAddress(value.getUnsignedValue().longValue());
	}

	/**
	 * Get the program counter from the innermost frame of the given thread's stack
	 * 
	 * <p>
	 * This will prefer the program counter in the {@link TraceStackFrame}. If that's not available,
	 * it will use the value of the program counter register from the thread's register bank for
	 * frame 0.
	 * 
	 * @param platform the platform
	 * @param thread the thread
	 * @param snap the snapshot key
	 * @return the address
	 */
	public static Address getProgramCounter(TracePlatform platform, TraceThread thread, long snap) {
		Address pcFromStack = getProgramCounterFromStack(platform, thread, snap);
		if (pcFromStack != null) {
			return pcFromStack;
		}
		return getProgramCounterFromRegisters(platform, thread, snap);
	}

	/**
	 * Check if the unwound frames annotated in the listing are "fresh"
	 * 
	 * <p>
	 * It can be difficult to tell. The heuristic we use is if the PC of the innermost frame agrees
	 * with the PC recorded for the current thread.
	 * 
	 * @param tool the tool
	 * @param coordinates the coordinates
	 * @return true if the unwind appears fresh
	 */
	public static boolean hasFreshUnwind(PluginTool tool, DebuggerCoordinates coordinates) {
		ListingUnwoundFrame innermost = locateInnermost(tool, coordinates);
		if (innermost == null || !Objects.equals(innermost.getProgramCounter(),
			getProgramCounter(coordinates.getPlatform(), coordinates.getThread(),
				coordinates.getViewSnap()))) {
			return false;
		}
		return true;
	}

	/**
	 * Find the function's variable whose storage is exactly the given register
	 * 
	 * @param function the function
	 * @param register the register
	 * @return the variable, or null
	 */
	public static Variable findVariable(Function function, Register register) {
		for (Variable variable : function.getAllVariables()) {
			if (variable.isRegisterVariable() && variable.getRegister() == register) {
				return variable;
			}
		}
		return null;
	}

	/**
	 * Find the fuction's variable whose storage contains the given stack offset
	 * 
	 * @param function the function
	 * @param stackAddress the stack offset
	 * @return the variable, or null
	 */
	public static Variable findStackVariable(Function function, Address stackAddress) {
		if (!stackAddress.isStackAddress()) {
			throw new IllegalArgumentException("stackAddress is not a stack address");
		}
		return function.getStackFrame().getVariableContaining((int) stackAddress.getOffset());
	}

	/**
	 * Convert the given varnode to an address range
	 * 
	 * @param vn the varnode
	 * @return the address range
	 */
	public static AddressRange rangeFromVarnode(Varnode vn) {
		return new AddressRangeImpl(vn.getAddress(), vn.getAddress().add(vn.getSize() - 1));
	}

	/**
	 * Check if the given address set completely contains the given varnode
	 * 
	 * @param set the set
	 * @param vn the varnode
	 * @return true if completely contained
	 */
	public static boolean containsVarnode(AddressSetView set, Varnode vn) {
		return set.contains(vn.getAddress(), vn.getAddress().add(vn.getSize() - 1));
	}

	/**
	 * Collect the addresses used for storage by any symbol in the given line of decompiled C code
	 * 
	 * <p>
	 * It's not the greatest, but any variable to be evaluated should only be expressed in terms of
	 * symbols on the same line (at least by the decompiler's definition, wrapping shouldn't count
	 * against us). This can be used to determine where evaluation should cease descending into
	 * defining p-code ops. See {@link #requiresFrame(PcodeOp, AddressSetView)}, and
	 * {@link UnwoundFrame#evaluate(Program, PcodeOp, AddressSetView)}.
	 * 
	 * @param line the line
	 * @return the address set
	 */
	public static AddressSet collectSymbolStorage(ClangLine line) {
		AddressSet storage = new AddressSet();
		for (ClangToken tok : line.getAllTokens()) {
			Varnode vn = tok.getVarnode();
			if (vn != null) {
				storage.add(rangeFromVarnode(vn));
			}
			HighVariable hVar = tok.getHighVariable();
			if (hVar == null) {
				continue;
			}
			Varnode rep = hVar.getRepresentative();
			if (rep != null) {
				storage.add(rangeFromVarnode(rep));
			}
			HighSymbol hSym = hVar.getSymbol();
			if (hSym == null) {
				continue;
			}
			for (Varnode stVn : hSym.getStorage().getVarnodes()) {
				storage.add(rangeFromVarnode(stVn));
			}
		}
		return storage;
	}

	/**
	 * Find the descendent that dereferences this given varnode
	 * 
	 * <p>
	 * This searches only one hop for a {@link PcodeOp#LOAD} or {@link PcodeOp#STORE}. If it find a
	 * load, it simply returns it. If it find a store, it generates the inverse load and returns it.
	 * This latter behavior ensures we can evaluate the lval or a decompiled assignment statement.
	 * 
	 * @param factory an address factory for generating unique varnodes
	 * @param vn the varnode for which a dereference is expected
	 * @return the dereference, as a {@link PcodeOp#LOAD}
	 */
	public static PcodeOp findDeref(AddressFactory factory, Varnode vn) {
		Iterable<PcodeOp> it = (Iterable<PcodeOp>) () -> vn.getDescendants();
		for (PcodeOp desc : it) {
			if (desc.getOpcode() == PcodeOp.LOAD) {
				return desc;
			}
		}
		for (PcodeOp desc : it) {
			if (desc.getOpcode() == PcodeOp.STORE) {
				PcodeOpAST op = new PcodeOpAST(desc.getSeqnum(), PcodeOp.LOAD, 2);
				op.setInput(desc.getInput(0), 0);
				op.setInput(desc.getInput(1), 1);
				VarnodeAST out = new VarnodeAST(factory.getUniqueSpace().getAddress(1L << 31),
					desc.getInput(2).getSize(), 0xf00d);
				op.setOutput(out);
				out.setDef(op);
				return op;
			}
		}
		return null;
	}

	/**
	 * Find an instance that occurs in the variable's symbol's storage
	 * 
	 * <p>
	 * This goal is to find a stable location for evaluating the high variable, rather than some
	 * temporary register or worse unique location. If no satisfying instance is found, it defaults
	 * to the variable's representative instance.
	 * 
	 * @param hVar the high variable
	 * @return the instance found
	 */
	public static Varnode getInstanceInSymbolStorage(HighVariable hVar) {
		Varnode representative = hVar.getRepresentative();
		HighSymbol hSym = hVar.getSymbol();
		if (hSym == null) {
			return representative;
		}
		AddressSet storageSet = new AddressSet();
		for (Varnode vn : hSym.getStorage().getVarnodes()) {
			storageSet.add(rangeFromVarnode(vn));
		}
		if (containsVarnode(storageSet, representative)) {
			return representative;
		}
		for (Varnode instance : hVar.getInstances()) {
			if (containsVarnode(storageSet, instance)) {
				return instance;
			}
		}
		return representative;
	}

	/**
	 * Create a {@link VariableStorage} object for the given high variable
	 * 
	 * <p>
	 * This is not necessarily the same as the variable's symbol's storage. In fact, if the variable
	 * represents a field, it is likely a subset of the symbol's storage.
	 * 
	 * @param hVar the high variable
	 * @return the storage
	 */
	public static VariableStorage fabricateStorage(HighVariable hVar) {
		try {
			return new VariableStorage(hVar.getHighFunction().getFunction().getProgram(),
				getInstanceInSymbolStorage(hVar));
		}
		catch (InvalidInputException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * A class which supports evaluating variables
	 */
	public static class VariableEvaluator {
		/**
		 * A listener that invalidates the stack unwind whenever the trace's bytes change
		 */
		private class ListenerForChanges extends TraceDomainObjectListener {
			public ListenerForChanges() {
				listenFor(TraceMemoryBytesChangeType.CHANGED, this::bytesChanged);
			}

			private void bytesChanged(TraceAddressSpace space, TraceAddressSnapRange range) {
				TraceThread thread = space.getThread();
				// TODO: Consider the lifespan, too? Would have to use viewport....
				if (thread == null || thread == coordinates.getThread()) {
					invalidateCache();
				}
			}
		}

		private final Object lock = new Object();
		private final PluginTool tool;
		private final DebuggerCoordinates coordinates;
		private final Language language;
		private final ListenerForChanges listenerForChanges = new ListenerForChanges();

		private List<UnwoundFrame<WatchValue>> unwound;
		private FakeUnwoundFrame<WatchValue> fakeFrame;

		/**
		 * Construct an evaluator for the given tool and coordinates
		 * 
		 * @param tool the tool
		 * @param coordinates the coordinates
		 */
		public VariableEvaluator(PluginTool tool, DebuggerCoordinates coordinates) {
			this.tool = tool;
			this.coordinates = coordinates;
			this.language = coordinates.getPlatform().getLanguage();

			coordinates.getTrace().addListener(listenerForChanges);
		}

		/**
		 * Dispose of this evaluator, removing its listener
		 */
		public void dispose() {
			coordinates.getTrace().removeListener(listenerForChanges);
		}

		/**
		 * Invalidate the stack unwind
		 */
		public void invalidateCache() {
			synchronized (lock) {
				unwound = null;
			}
		}

		/**
		 * Get a fake frame for global / static variables
		 * 
		 * @return the fake frame
		 */
		public UnwoundFrame<WatchValue> getGlobalsFakeFrame() {
			synchronized (lock) {
				if (fakeFrame == null) {
					fakeFrame = new FakeUnwoundFrame<>(tool, coordinates,
						DebuggerPcodeUtils.buildWatchState(tool, coordinates.frame(0)));
				}
				return fakeFrame;
			}
		}

		/**
		 * Refresh the stack unwind
		 * 
		 * @param monitor a monitor for cancellation
		 */
		protected void doUnwind(TaskMonitor monitor) {
			monitor.setMessage("Unwinding Stack");
			StackUnwinder unwinder = new StackUnwinder(tool, coordinates.getPlatform());
			unwound = new ArrayList<>();
			for (AnalysisUnwoundFrame<WatchValue> frame : unwinder.frames(coordinates.frame(0),
				monitor)) {
				unwound.add(frame);
			}
		}

		/**
		 * Get the stack frame for the given function at or beyond the coordinates' frame level
		 * 
		 * @param function the desired function
		 * @param warnings a place to emit warnings
		 * @param monitor a monitor for cancellation
		 * @param required whether to throw an exception or register a warning
		 * @return the frame if found, or null
		 */
		public UnwoundFrame<WatchValue> getStackFrame(Function function,
				StackUnwindWarningSet warnings, TaskMonitor monitor, boolean required) {
			synchronized (lock) {
				if (unwound == null) {
					try {
						doUnwind(monitor);
					}
					catch (Exception e) {
						/**
						 * Most exceptions should be caught and wrapped by the unwind analysis. If
						 * one gets here, something bad has happened, and for debugging purposes, we
						 * should invalidate, so that the error will repeat next time the frame is
						 * requested.
						 */
						unwound = null;
						throw e;
					}
				}

				for (UnwoundFrame<WatchValue> frame : unwound.subList(coordinates.getFrame(),
					unwound.size())) {
					if (frame.getFunction() == function) {
						StackUnwindWarningSet unwindWarnings = frame.getWarnings();
						if (unwindWarnings != null) {
							warnings.addAll(unwindWarnings);
						}
						return frame;
					}
				}
				String message;
				if (unwound.isEmpty()) {
					message = "Could not recover the innermost frame!";
				}
				else {
					message = "There is no frame for %s among the %d frames unwound."
							.formatted(function, unwound.size());
					Exception error = unwound.get(unwound.size() - 1).getError();
					if (error != null) {
						message += "\nTerminating error: %s".formatted(error.getMessage());
					}
				}
				if (required) {
					throw new UnwindException(message);
				}
				warnings.add(new CustomStackUnwindWarning(message));
				return null;
			}
		}

		/**
		 * Get the data unit for a register
		 * 
		 * <p>
		 * This accounts for memory-mapped registers.
		 * 
		 * @param register the register
		 * @return the data unit, or null if undefined or mismatched
		 */
		public TraceData getRegisterUnit(Register register) {
			TraceCodeOperations code;
			TraceCodeManager codeManager = coordinates.getTrace().getCodeManager();
			if (register.getAddressSpace().isRegisterSpace()) {
				TraceThread thread = coordinates.getThread();
				if (thread == null) {
					return null;
				}
				code = codeManager.getCodeRegisterSpace(thread, false);
				if (code == null) {
					return null;
				}
			}
			else {
				code = codeManager;
			}
			return code.definedData()
					.getForRegister(coordinates.getPlatform(), coordinates.getViewSnap(), register);
		}

		/**
		 * Obtain the value of a register
		 * 
		 * <p>
		 * In order to accommodate user-provided types on registers, it's preferable to obtain the
		 * data unit using {@link #getRegisterUnit(Register)}. Fall back to this method only if that
		 * one fails.
		 * 
		 * @param register
		 * @return
		 */
		public WatchValue getRawRegisterValue(Register register) {
			WatchValuePcodeExecutorState state =
				DebuggerPcodeUtils.buildWatchState(tool, coordinates.frame(0));
			return state.getVar(register, Reason.INSPECT);
		}

		/**
		 * Get the representation of a variable's value according to a given data type
		 * 
		 * @param address the best static address giving the location of the variable
		 * @param bytes the bytes giving the variable's value
		 * @param type the type of the variable
		 * @param settings settings to configure the data type
		 * @return the string representation, or null
		 */
		public String getRepresentation(Address address, byte[] bytes, DataType type,
				Settings settings) {
			if (type instanceof Pointer && !AddressSpaceSettingsDefinition.DEF.hasValue(settings) &&
				address.isRegisterAddress()) {
				settings = new DefaultSpaceSettings(settings, language.getDefaultSpace());
			}
			ByteMemBufferImpl buf =
				new ByteMemBufferImpl(address, bytes, language.isBigEndian()) {
					@Override
					public Memory getMemory() {
						return coordinates.getView().getMemory();
					}
				};
			return type.getRepresentation(buf, settings, bytes.length);
		}

		/**
		 * Get the representation of a variable's value according to a given data type
		 * 
		 * @param frame the frame that evaluated the variable's value
		 * @param address the best static address giving the location of the variable. Note that the
		 *            address given by {@link WatchValue#address()} is its dynamic address. The
		 *            static address should instead be taken from the variable's storage or a p-code
		 *            op's output varnode.
		 * @param value the value of the variable
		 * @param type the type of the variable
		 * @return the string representation, or null
		 */
		public String getRepresentation(UnwoundFrame<?> frame, Address address, WatchValue value,
				DataType type) {
			if (type == DataType.DEFAULT) {
				return null;
			}
			Settings settings = type.getDefaultSettings();
			if (address.isStackAddress()) {
				address = frame.getBasePointer().add(address.getOffset());
				if (frame instanceof ListingUnwoundFrame listingFrame) {
					settings = listingFrame.getComponentContaining(address);
				}
			}
			return getRepresentation(address, value.bytes().bytes(), type, settings);
		}
	}
}
