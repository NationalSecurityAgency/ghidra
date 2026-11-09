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
package ghidra.app.plugin.core.debug.gui.slice;

import docking.action.builder.ActionBuilder;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.model.Trace;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public class ForwardSliceProvider extends AbstractSliceProvider {

	@Override
	SliceDirection getDirection() {
		return SliceDirection.FORWARD;
	}

	public ForwardSliceProvider(DebuggerTraceSlicePlugin plugin, Trace trace, CodeUnit unit,
			long snap) {
		super(plugin, "Slice Forward", trace, unit, snap);
	}

	ForwardSliceProvider(DebuggerTraceSlicePlugin plugin, Trace trace) {
		super(plugin, "Slice Forward", trace, null, 0, false);
	}

	@Override
	protected void createActions() {
		super.createActions();
		String owner = plugin.getName();
		new ActionBuilder("Find Actual Uses", owner)
				.popupMenuPath("Actual Uses")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindActualUses)
				.onAction(this::activateFindActualUses)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Actual Outputs", owner)
				.popupMenuPath("Actual Outputs")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindActualOutputs)
				.onAction(this::activateFindActualOutputs)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Actual Branch From", owner)
				.popupMenuPath("Actual Branch From")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindActualBranchFrom)
				.onAction(this::activateFindActualBranchFrom)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Static Uses", owner)
				.popupMenuPath("Static Uses")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindStaticUses)
				.onAction(this::activateFindStaticUses)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Static Outputs", owner)
				.popupMenuPath("Static Outputs")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindStaticOutputs)
				.onAction(this::activateFindStaticOutputs)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Static Branch From", owner)
				.popupMenuPath("Static Branch From")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindStaticBranchFrom)
				.onAction(this::activateFindStaticBranchFrom)
				.buildAndInstallLocal(this);
		new ActionBuilder("Follow Static Flows From", owner)
				.popupMenuPath("Static Flows From")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFollowStaticFlowsFrom)
				.onAction(this::activateFollowStaticFlowsFrom)
				.buildAndInstallLocal(this);
		// Add examine path action
		createExaminePathAction();
	}

	private boolean enableFindActualUses(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof UnitSliceNode<?> && n.displaySnap());
	}

	private void activateFindActualUses(SliceActionContext ctx) {
		var ms = tool.getService(DebuggerStaticMappingService.class);
		for (var node : ctx.getSelection()) {
			if (node instanceof UnitSliceNode<?> un) {
				un.descendActualUses(ms);
				un.setExpanded(true);
			}
		}
		model.reload();
	}

	private boolean enableFindActualOutputs(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof InstructionSliceNode && n.displaySnap());
	}

	private void activateFindActualOutputs(SliceActionContext ctx) {
		var ms = tool.getService(DebuggerStaticMappingService.class);
		for (var node : ctx.getSelection()) {
			if (node instanceof UnitSliceNode<?> unit) {
				unit.descendActualOutputs(ms);
				unit.setExpanded(true);
			}
		}
		model.reload();
	}

	private boolean enableFindActualBranchFrom(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof InstructionSliceNode && n.displaySnap());
	}

	private void activateFindActualBranchFrom(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		new TaskLauncher(new Task("Find Next Conditional/Indirect Branch") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof InstructionSliceNode in) {
						in.descendActualBranchFrom(monitor, ms);
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}

	private boolean enableFindStaticUses(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof UnitSliceNode<?> u && u.getStaticPc() != null);
	}

	private void activateFindStaticUses(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		new TaskLauncher(new Task("Find Static Uses") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof UnitSliceNode<?> unit) {
						unit.descendStaticUses(ms, monitor);
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}

	private boolean enableFindStaticOutputs(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof InstructionSliceNode && n.getStaticPc() != null);
	}

	private void activateFindStaticOutputs(SliceActionContext ctx) {
		var ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		for (var node : ctx.getSelection()) {
			if (node instanceof InstructionSliceNode in) {
				in.descendStaticOutputs(ms);
				in.setExpanded(true);
			}
		}
		model.reload();
	}

	private boolean enableFindStaticBranchFrom(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof InstructionSliceNode && n.getStaticPc() != null);
	}

	private void activateFindStaticBranchFrom(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		new TaskLauncher(new Task("Find Static Next Conditional/Indirect Branch") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof InstructionSliceNode instruction) {
						instruction.descendStaticBranchFrom(ms, monitor);
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}

	private boolean enableFollowStaticFlowsFrom(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof InstructionSliceNode && n.getStaticPc() != null);
	}

	private void activateFollowStaticFlowsFrom(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		new TaskLauncher(new Task("Follow Static Flows") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof InstructionSliceNode in) {
						in.descendStaticFlows(ms, monitor);
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}
}
