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
package ghidra.app.plugin.core.debug.workflow;

import java.util.*;
import java.util.Map.Entry;

import javax.swing.event.ChangeListener;

import com.google.common.collect.Range;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.debug.service.workflow.*;
import ghidra.app.services.DebuggerBot;
import ghidra.app.services.DebuggerBotInfo;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.annotation.HelpInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

@DebuggerBotInfo( //
	description = "Disassemble memory at the program counter", //
	details = "Listens for changes in memory or pc (stack or registers) and disassembles", //
	help = @HelpInfo(anchor = "disassemble_at_pc"), //
	enabledByDefault = true //
)
public class DisassembleAtPcDebuggerBot implements DebuggerBot {

	protected class ForDisassemblyTraceListener extends AbstractMultiToolTraceListener {
		private final TraceStackManager stackManager;
		private final TraceMemoryManager memoryManager;
		private final TraceCodeManager codeManager;
		private final TraceTimeViewport viewport;

		private final Register pc;
		private final AddressRange pcRange;

		private final Set<DisassemblyInject> injects = new LinkedHashSet<>();
		private final ChangeListener injectsChangeListener = e -> updateInjects();

		// Offload disassembly evaluation from swing thread
		private final Deque<Runnable> runQueue = new LinkedList<>();
		private final AsyncDebouncer<Void> runDebouncer =
			new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);

		public ForDisassemblyTraceListener(Trace trace) {
			super(trace);
			this.stackManager = trace.getStackManager();
			this.memoryManager = trace.getMemoryManager();
			this.codeManager = trace.getCodeManager();
			this.viewport = trace.getProgramView().getViewport();

			this.pc = trace.getBaseLanguage().getProgramCounter();
			this.pcRange = TraceRegisterUtils.rangeForRegister(pc);

			ClassSearcher.addChangeListener(injectsChangeListener);
			updateInjects();

			runDebouncer.addListener(this::processQueue);

			listenFor(TraceMemoryBytesChangeType.CHANGED, this::valuesChanged);
			listenFor(TraceStackChangeType.CHANGED, this::stackChanged);

			// Do initial analysis? 
		}

		private void updateInjects() {
			synchronized (injects) {
				injects.clear();
				ClassSearcher.getInstances(DisassemblyInject.class)
						.stream()
						.filter(i -> i.isApplicable(trace))
						.sorted(Comparator.comparing(i -> i.getPriority()))
						.forEach(injects::add);
			}
		}

		private void queueRunnable(Runnable r) {
			synchronized (runQueue) {
				runQueue.add(r);
			}
			runDebouncer.contact(null);
		}

		private void processQueue(Void __) {
			try {
				List<Runnable> copy;
				synchronized (runQueue) {
					copy = List.copyOf(runQueue);
					runQueue.clear();
				}
				for (Runnable r : copy) {
					r.run();
				}
			}
			catch (Throwable e) {
				Msg.error(this, "Error processing queue", e);
			}
		}

		private void valuesChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				byte[] oldValue, byte[] newValue) {
			if (space.getAddressSpace().isRegisterSpace()) {
				registersChanged(space, range);
			}
			else {
				memoryChanged(range);
			}
		}

		private void stackChanged(TraceStack stack) {
			queueRunnable(() -> {
				disassembleStackPcVals(stack, stack.getSnap(), null);
			});
		}

		private long findNonScratchSnap(long snap) {
			if (snap >= 0) {
				return snap;
			}
			TraceViewportSpanIterator spit = new TraceViewportSpanIterator(trace, snap);
			while (spit.hasNext()) {
				Range<Long> span = spit.next();
				if (span.upperEndpoint() >= 0) {
					return span.upperEndpoint();
				}
			}
			return snap;
		}

		private void memoryChanged(TraceAddressSnapRange range) {
			if (!viewport.containsAnyUpper(range.getLifespan())) {
				return;
			}
			// This is a wonky case, because we care about where the user is looking.
			long pcSnap = trace.getProgramView().getSnap();
			long memSnap = range.getY1();
			queueRunnable(() -> {
				for (TraceThread thread : trace.getThreadManager()
						.getLiveThreads(findNonScratchSnap(pcSnap))) {
					TraceStack stack = stackManager.getLatestStack(thread, pcSnap);
					if (stack != null) {
						disassembleStackPcVals(stack, memSnap, range.getRange());
					}
					else {
						disassembleRegPcVal(thread, 0, pcSnap, memSnap);
					}
				}
			});
		}

		private void registersChanged(TraceAddressSpace space, TraceAddressSnapRange range) {
			queueRunnable(() -> {
				if (space.getFrameLevel() != 0) {
					return;
				}
				if (!range.getRange().intersects(pcRange)) {
					return;
				}
				TraceThread thread = space.getThread();
				long snap = range.getY1();
				if (stackManager.getLatestStack(thread, snap) != null) {
					return;
				}
				disassembleRegPcVal(thread, space.getFrameLevel(), snap, snap);
			});
		}

		protected void disassembleStackPcVals(TraceStack stack, long memSnap, AddressRange range) {
			TraceStackFrame frame = stack.getFrame(0, false);
			if (frame == null) {
				return;
			}
			Address pcVal = frame.getProgramCounter();
			if (pcVal == null) {
				return;
			}
			if (range == null || range.contains(pcVal)) {
				// NOTE: If non-0 frames are ever used, level should be passed in for injects
				disassemble(pcVal, stack.getThread(), memSnap);
			}
		}

		protected void disassembleRegPcVal(TraceThread thread, int frameLevel, long pcSnap,
				long memSnap) {
			TraceData pcUnit = null;
			try (UndoableTransaction tid =
				UndoableTransaction.start(trace, "Disassemble: PC is code pointer", true)) {
				TraceCodeRegisterSpace regCode =
					codeManager.getCodeRegisterSpace(thread, frameLevel, true);
				try {
					pcUnit = regCode.definedData()
							.create(Range.atLeast(pcSnap), pc, PointerDataType.dataType);
				}
				catch (CodeUnitInsertionException e) {
					// I guess something's already there. Leave it, then!
					// Try to get it, in case it's already a pointer type
					pcUnit = regCode.definedData().getForRegister(pcSnap, pc);
				}
			}
			if (pcUnit != null) {
				Address pcVal = (Address) TraceRegisterUtils.getValueHackPointer(pcUnit);
				if (pcVal != null) {
					disassemble(pcVal, thread, memSnap);
				}
			}
		}

		protected Long isKnownRWOrEverKnownRO(Address start, long snap) {
			Entry<Long, TraceMemoryState> kent = memoryManager.getViewState(snap, start);
			if (kent != null && kent.getValue() == TraceMemoryState.KNOWN) {
				return kent.getKey();
			}
			Entry<TraceAddressSnapRange, TraceMemoryState> mrent =
				memoryManager.getViewMostRecentStateEntry(snap, start);
			if (mrent == null || mrent.getValue() != TraceMemoryState.KNOWN) {
				// It has never been known up to this snap
				return null;
			}
			TraceMemoryRegion region =
				memoryManager.getRegionContaining(mrent.getKey().getY1(), start);
			if (region == null || region.isWrite()) {
				// It could have changed this snap, so unknown
				return null;
			}
			return mrent.getKey().getY1();
		}

		protected void disassemble(Address start, TraceThread thread, long snap) {
			Long knownSnap = isKnownRWOrEverKnownRO(start, snap);
			if (knownSnap == null) {
				return;
			}
			long ks = knownSnap;
			if (codeManager.definedUnits().containsAddress(ks, start)) {
				return;
			}

			/**
			 * TODO: Is this composition of laziness upon laziness efficient enough?
			 * 
			 * <p>
			 * Can experiment with ordering of address-set-view "expression" to optimize early
			 * termination.
			 * 
			 * <p>
			 * Want addresses satisfying {@code known | (readOnly & everKnown)}
			 */
			AddressSetView readOnly =
				memoryManager.getRegionsAddressSetWith(ks, r -> !r.isWrite());
			AddressSetView everKnown = memoryManager.getAddressesWithState(Range.atMost(ks),
				s -> s == TraceMemoryState.KNOWN);
			AddressSetView roEverKnown = new IntersectionAddressSetView(readOnly, everKnown);
			AddressSetView known =
				memoryManager.getAddressesWithState(ks, s -> s == TraceMemoryState.KNOWN);
			AddressSetView disassemblable =
				new AddressSet(new UnionAddressSetView(known, roEverKnown));

			// TODO: Should I just keep a variable-snap view around?
			TraceProgramView view = trace.getFixedProgramView(ks);
			DisassembleCommand dis =
				new DisassembleCommand(start, disassemblable, true) {
					@Override
					public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
						synchronized (injects) {
							if (codeManager.definedUnits().containsAddress(ks, start)) {
								return true;
							}
							for (DisassemblyInject i : injects) {
								i.pre(plugin.getTool(), this, view, thread,
									new AddressSet(start, start),
									disassemblable);
							}
							boolean result = super.applyTo(obj, monitor);
							if (!result) {
								return false;
							}
							for (DisassemblyInject i : injects) {
								i.post(plugin.getTool(), view, getDisassembledAddressSet());
							}
							return result;
						}
					}
				};
			// TODO: Queue commands so no two for the same trace run concurrently
			plugin.getTool().executeBackgroundCommand(dis, view);
		}
	}

	private DebuggerWorkflowServicePlugin plugin;
	private final MultiToolTraceListenerManager<ForDisassemblyTraceListener> listeners =
		new MultiToolTraceListenerManager<>(ForDisassemblyTraceListener::new);

	@Override
	public boolean isEnabled() {
		return plugin != null;
	}

	@Override
	public void enable(DebuggerWorkflowServicePlugin wp) {
		this.plugin = wp;

		listeners.enable(wp);
	}

	@Override
	public void disable() {
		this.plugin = null;

		listeners.disable();
	}

	@Override
	public void traceOpened(PluginTool tool, Trace trace) {
		listeners.traceOpened(tool, trace);
	}

	@Override
	public void traceClosed(PluginTool tool, Trace trace) {
		listeners.traceClosed(tool, trace);
	}
}
