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
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.UnionAddressSetView;
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

		private final Register pc;
		private final AddressRange pcRange;

		private boolean usesStacks = false;

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
			List<Runnable> copy;
			synchronized (runQueue) {
				copy = List.copyOf(runQueue);
				runQueue.clear();
			}
			for (Runnable r : copy) {
				r.run();
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
				usesStacks = true;
				disassembleStackPcVals(stack, stack.getSnap(), null);
			});
		}

		private void memoryChanged(TraceAddressSnapRange range) {
			queueRunnable(() -> {
				long snap = range.getY1();
				for (TraceThread thread : trace.getThreadManager().getLiveThreads(snap)) {
					TraceStack stack = stackManager.getLatestStack(thread, snap);
					if (stack != null) {
						usesStacks = true;
						disassembleStackPcVals(stack, snap, range.getRange());
					}
					disassembleRegPcVal(thread, 0, snap);
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
				disassembleRegPcVal(space.getThread(), space.getFrameLevel(), range.getY1());
			});
		}

		protected void disassembleStackPcVals(TraceStack stack, long snap, AddressRange range) {
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
				disassemble(pcVal, stack.getThread(), snap);
			}
		}

		protected void disassembleRegPcVal(TraceThread thread, int frameLevel, long snap) {
			TraceData pcUnit = null;
			try (UndoableTransaction tid =
				UndoableTransaction.start(trace, "Disassemble: PC is code pointer", true)) {
				TraceCodeRegisterSpace regCode =
					codeManager.getCodeRegisterSpace(thread, frameLevel, true);
				try {
					pcUnit = regCode.definedData()
							.create(Range.atLeast(snap), pc, PointerDataType.dataType);
				}
				catch (CodeUnitInsertionException e) {
					// I guess something's already there. Leave it, then!
					// Try to get it, in case it's already a pointer type
					pcUnit = regCode.definedData().getForRegister(snap, pc);
				}
			}
			if (!usesStacks && pcUnit != null) {
				Address pcVal = (Address) TraceRegisterUtils.getValueHackPointer(pcUnit);
				if (pcVal != null) {
					disassemble(pcVal, thread, snap);
				}
			}
		}

		protected boolean isKnownRWOrEverKnownRO(Address start, long snap) {
			Entry<TraceAddressSnapRange, TraceMemoryState> ent =
				memoryManager.getMostRecentStateEntry(snap, start);
			if (ent == null || ent.getValue() != TraceMemoryState.KNOWN) {
				// It has never been known up to this snap
				return false;
			}
			if (ent.getKey().getLifespan().contains(snap)) {
				// It is known at this snap, so RO vs RW is irrelevant
				return true;
			}
			TraceMemoryRegion region = memoryManager.getRegionContaining(snap, start);
			if (region.isWrite()) {
				// It could have changed this snap, so unknown
				return false;
			}
			return true;
		}

		protected void disassemble(Address start, TraceThread thread, long snap) {
			if (!isKnownRWOrEverKnownRO(start, snap)) {
				return;
			}
			if (codeManager.definedUnits().containsAddress(snap, start)) {
				return;
			}

			/**
			 * TODO: Is this composition of laziness upon laziness efficient enough?
			 * 
			 * Can experiment with ordering of address-set-view "expression" to optimize early
			 * termination.
			 * 
			 * Want addresses satisfying {@code known | (readOnly & everKnown)}
			 */
			AddressSetView readOnly =
				memoryManager.getRegionsAddressSetWith(snap, r -> !r.isWrite());
			AddressSetView everKnown = memoryManager.getAddressesWithState(Range.atMost(snap),
				s -> s == TraceMemoryState.KNOWN);
			AddressSetView roEverKnown = new IntersectionAddressSetView(readOnly, everKnown);
			AddressSetView known =
				memoryManager.getAddressesWithState(snap, s -> s == TraceMemoryState.KNOWN);
			AddressSetView disassemblable = new UnionAddressSetView(known, roEverKnown);

			// TODO: Should I just keep a variable-snap view around?
			TraceProgramView view = trace.getFixedProgramView(snap);
			DisassembleCommand dis =
				new DisassembleCommand(start, disassemblable, true) {
					@Override
					public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
						synchronized (injects) {
							if (codeManager.definedUnits().containsAddress(snap, start)) {
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
