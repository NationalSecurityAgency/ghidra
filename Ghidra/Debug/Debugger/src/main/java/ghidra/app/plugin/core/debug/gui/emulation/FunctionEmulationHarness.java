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
package ghidra.app.plugin.core.debug.gui.emulation;

import java.io.IOException;
import java.util.*;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.gui.emulation.LocAndVal.WriterAndExecutor;
import ghidra.app.plugin.core.debug.service.breakpoint.ProgramBreakpoint;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationIntegration;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.emulation.data.TranslatedPcodeDebuggerAccess;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingContext;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingContext.ChangeCollector;
import ghidra.app.plugin.core.debug.stack.*;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.*;
import ghidra.pcode.eval.ArithmeticVarnodeEvaluator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.task.TaskMonitor;

public class FunctionEmulationHarness implements AutoCloseable {

	public record ProbeOut(Varnode vn, byte[] value) {
		public String toString(Language language) {
			return "%s = %s (%s)".formatted(vn.toString(language),
				NumericUtilities.convertBytesToString(value, ":"),
				Utils.bytesToBigInteger(value, vn.getSize(), language.isBigEndian(), false));
		}
	}

	public record ReturnAddressInfo(Address location, long mask) {
		public Address computePhysicalLocation(Eval eval, CompilerSpec cSpec) {
			if (location.isMemoryAddress() || location.isRegisterAddress()) {
				return location;
			}
			if (location.isStackAddress()) {
				Register sp = cSpec.getStackPointer();
				LocAndVal spVal = eval.state.getVar(sp, Reason.INSPECT);
				Address stackBase = eval.state.getArithmetic()
						.toAddress(spVal, cSpec.getStackBaseSpace(), Purpose.INSPECT);
				return stackBase.add(location.getOffset());
			}
			throw new IllegalStateException("Unknown space for return address location");
		}
	}

	public ReturnAddressInfo locateReturnAddress() {
		UnwindAnalysis unwindAnalysis = new UnwindAnalysis(program);
		try {
			UnwindInfo unwindInfo = unwindAnalysis.getUnwindInfo(function.getEntryPoint(), monitor);
			return new ReturnAddressInfo(unwindInfo.ofReturn(), unwindInfo.maskOfReturn());
		}
		catch (UnwindException e) {
			return null;
		}
	}

	public static FunctionEmulationHarness start(PluginTool tool, Function function,
			TaskMonitor monitor) throws IOException {
		ManagedDomainObject<Trace> mt = new ManagedDomainObject<Trace>(mdo -> ProgramEmulationUtils
				.launchEmulationTrace(function.getProgram(), function.getEntryPoint(), mdo));
		return new FunctionEmulationHarness(tool, mt, function, monitor);
	}

	public class Eval {
		public final long snap;
		public final Writer writer;
		public final PcodeExecutor<LocAndVal> exec;
		public final PcodeExecutorState<LocAndVal> state;

		private Eval(long snap) {
			this.snap = snap;
			WriterAndExecutor we = LocAndVal.buildExecutor(tool, start.snap(snap));
			this.writer = we.writer();
			this.exec = we.executor();
			this.state = exec.getState();
		}

		public void writeNode(VarStorageNode node, LocAndVal value) {
			LocAndVal cur = node.compile(language).evaluate(exec);
			exec.getState().setVar(cur.loc().getAddress(), node.size(), false, value);
		}

		public void writeVariable(VarStorage storage, LocAndVal value) {
			int shift = 0;
			for (VarStorageNode n : storage.nodes()) {
				LocAndVal piece = lvArith.binaryOp(PcodeOp.INT_RIGHT, n.size(),
					value.value().length, value, 4, lvArith.fromConst(shift, 4));
				shift += n.size();
				writeNode(n, piece);
			}
		}

		public void writeVariable(VarStorage storage, byte[] value) {
			writeVariable(storage, lvArith.fromConst(value));
		}

		public void commit() {
			writer.writeDown(snap);
		}

		public LocAndVal readNode(VarStorageNode node) {
			return node.compile(language).evaluate(exec);
		}

		public LocAndVal readVariable(VarStorage storage) {
			int total = storage.size();
			LocAndVal value = lvArith.fromConst(0, total);
			for (VarStorageNode n : storage.nodes()) {
				LocAndVal piece = readNode(n);
				value = ArithmeticVarnodeEvaluator.catenate(lvArith, total, value, piece, n.size());
			}
			return value;
		}
	}

	class MonitoredCallbacks extends ComposedPcodeEmulationCallbacks<byte[]> {
		public MonitoredCallbacks(PcodeEmulationCallbacks<byte[]> cb) {
			super(cb);
		}

		@Override
		public void beforeStepOp(PcodeThread<byte[]> thread, PcodeOp op, PcodeFrame frame) {
			if (monitor.isCancelled()) {
				throw new InterruptPcodeExecutionException(frame, null);
			}
		}
	}

	public class OverrideProbeUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		@PcodeUserop
		public void emu_probe(@OpExecutor PcodeExecutor<byte[]> exec, Varnode in) {
			probesOut.add(new ProbeOut(in, exec.getState().getVar(in, Reason.INSPECT)));
		}
	}

	class MonitoredEmulator extends PcodeEmulator {
		public MonitoredEmulator(Language language, PcodeEmulationCallbacks<byte[]> cb) {
			super(language, new MonitoredCallbacks(cb));
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			return super.createUseropLibrary().compose(new OverrideProbeUseropLibrary(), true);
		}
	}

	final PluginTool tool;
	final ManagedDomainObject<Trace> mt;
	final Transaction tx;
	public final Trace trace;
	final TraceThread thread;
	final DebuggerCoordinates start;
	final Eval initEval;
	public final PcodeArithmetic<LocAndVal> lvArith;
	final SleighLanguage language;
	final Function function;
	final Program program;
	final DebuggerAddressTranslator translator;
	final TaskMonitor monitor;

	final Writer writer;
	final PcodeEmulator emulator;
	final PcodeThread<byte[]> emuThread;

	final List<ProbeOut> probesOut = new ArrayList<>();

	private FunctionEmulationHarness(PluginTool tool, ManagedDomainObject<Trace> mt,
			Function function, TaskMonitor monitor) {
		this.tool = tool;
		this.mt = mt;
		this.trace = mt.get();
		this.tx = trace.openTransaction("Emulate");
		this.thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		this.start = DebuggerCoordinates.NOWHERE.thread(thread);
		this.initEval = new Eval(0);
		this.lvArith = initEval.exec.getArithmetic();
		this.language = initEval.exec.getLanguage();
		this.function = function;
		this.program = function.getProgram();
		this.monitor = monitor;

		TracePlatform host = trace.getPlatformManager().getHostPlatform();
		this.translator = getTranslator();
		PcodeDebuggerAccess access = new TranslatedPcodeDebuggerAccess(null, host, 0) {
			@Override
			public DebuggerAddressTranslator getAddressTranslator() {
				return translator;
			}
		};
		writer = DebuggerEmulationIntegration.bytesDelayedWriteTrace(access);
		emulator = new MonitoredEmulator(language, writer.callbacks());
		emuThread = emulator.newThread(thread.getPath());
	}

	private DebuggerAddressTranslator getTranslator() {
		// Don't use the service. It requires the trace and program to be opened in the tool
		DebuggerStaticMappingContext mapper = new DebuggerStaticMappingContext();
		try (ChangeCollector cc = mapper.collectChanges()) {
			mapper.addProgram(cc, program);
			mapper.addTrace(cc, trace);
		}
		return mapper;
	}

	public Eval init() {
		return initEval;
	}

	public Eval eval(long snap) {
		return new Eval(snap);
	}

	public void placeSentinel(Address sentinel) {
		ReturnAddressInfo retInfo = locateReturnAddress();
		if (retInfo == null) {
			Address zero = language.getDefaultSpace().getAddress(0);
			Msg.warn(this,
				"Could not locate return address. Placing end break at %s".formatted(zero));
			emulator.addBreakpoint(zero, SleighUtils.CONDITION_ALWAYS);
		}
		else {
			initEval.state.setVar(
				retInfo.computePhysicalLocation(initEval, program.getCompilerSpec()),
				language.getProgramCounter().getNumBytes(), false, lvArith.fromConst(sentinel));
			emulator.addBreakpoint(sentinel.getNewAddress(sentinel.getOffset() & retInfo.mask),
				SleighUtils.CONDITION_ALWAYS);
		}
	}

	public void installInjects() {
		Iterator<Bookmark> bit = program.getBookmarkManager()
				.getBookmarksIterator(LogicalBreakpoint.ENABLED_BOOKMARK_TYPE);
		while (bit.hasNext()) {
			ProgramBreakpoint brk = ProgramBreakpoint.fromBookmark(program, bit.next());
			String sleigh = brk.getEmuSleigh();
			if (sleigh == null || SleighUtils.UNCONDITIONAL_BREAK.equals(sleigh)) {
				continue;
			}
			emulator.inject(brk.getLocation().getAddress(), sleigh);
		}
	}

	public void createSnapshot(long snap) {
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, true);
		snapshot.setDescription("Emulated");
		snapshot.setEventThread(thread);
		writer.writeDown(snap);
	}

	public record EmulationResult(long snap, Throwable error) {
		/**
		 * In the case we terminate normally, we should probably ensure the {@code return}
		 * instruction highlighted. This can be accomplished by subtracting one from the last snap.
		 * For abnormal termination, I think we should just go to the last snap and let whatever
		 * problem(s) get displayed.
		 * 
		 * @return the last snap - 1 if successful, otherwise just the last snap.
		 */
		public long defaultSnap() {
			if (error == null) {
				return snap - 1;
			}
			return snap;
		}
	}

	public EmulationResult run(long snapshotPeriod) {
		long snap = 1;
		boolean makeFinalSnap = false;
		Throwable error = null;
		try {
			if (snapshotPeriod == 0) {
				makeFinalSnap = true;
				emuThread.run();
				throw new AssertionError("Shouldn't happen");
			}
			for (;; snap += 1) {
				emuThread.stepInstruction();
				makeFinalSnap = true;
				emuThread.stepInstruction(snapshotPeriod - 1);
				createSnapshot(snap);
				makeFinalSnap = false;
			}
		}
		catch (InterruptPcodeExecutionException e) {
			// Expected, but snap is now one ahead of the last snapshot
			snap--;
		}
		catch (Throwable t) {
			error = t;
			snap--;
		}
		if (makeFinalSnap) {
			createSnapshot(++snap);
		}
		return new EmulationResult(snap, error);
	}

	public List<ProbeOut> getProbesOut() {
		return probesOut;
	}

	@Override
	public void close() {
		tx.close();
		mt.close();
	}
}
