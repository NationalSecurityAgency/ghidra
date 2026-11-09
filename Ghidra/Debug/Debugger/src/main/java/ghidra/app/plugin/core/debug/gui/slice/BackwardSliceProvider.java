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

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;

import docking.action.builder.ActionBuilder;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.model.Trace;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public class BackwardSliceProvider extends AbstractSliceProvider {

	@Override
	SliceDirection getDirection() {
		return SliceDirection.BACKWARD;
	}

	public BackwardSliceProvider(DebuggerTraceSlicePlugin plugin, Trace trace, CodeUnit unit,
			long snap) {
		super(plugin, "Slice Backward", trace, unit, snap);
	}

	BackwardSliceProvider(DebuggerTraceSlicePlugin plugin, Trace trace) {
		super(plugin, "Slice Backward", trace, null, 0, false);
	}

	@Override
	protected void createActions() {
		super.createActions();
		String owner = plugin.getName();
		new ActionBuilder("Find Actual Definition", owner)
				.popupMenuPath("Actual Definition")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindActualDefinition)
				.onAction(this::activateFindActualDefinition)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Actual Inputs", owner)
				.popupMenuPath("Actual Inputs")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindActualInputs)
				.onAction(this::activateFindActualInputs)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Actual Conditional Branch To", owner)
				.popupMenuPath("Actual Conditional Branch To")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindActualConditionalBranchTo)
				.onAction(this::activateFindActualConditionalBranchTo)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Static Definitions", owner)
				.popupMenuPath("Static Definitions")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindStaticDefinitions)
				.onAction(this::activateFindStaticDefinitions)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Static Inputs", owner)
				.popupMenuPath("Static Inputs")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindStaticInputs)
				.onAction(this::activateFindStaticInputs)
				.buildAndInstallLocal(this);
		new ActionBuilder("Find Static Conditional Branches To", owner)
				.popupMenuPath("Static Conditional Branches")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableFindStaticConditionalBranchTo)
				.onAction(this::activateFindStaticConditionalBranchTo)
				.buildAndInstallLocal(this);
		new ActionBuilder("Search", owner)
				.popupMenuPath("Breadth-first Search...")
				.popupMenuGroup("Search")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableSearch)
				.onAction(this::activateSearch)
				.buildAndInstallLocal(this);
		// Add examine path action
		createExaminePathAction();
	}

	private boolean enableFindActualDefinition(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof UnitSliceNode && n.displaySnap());
	}

	private void activateFindActualDefinition(SliceActionContext ctx) {
		DebuggerStaticMappingService ms = tool.getService(DebuggerStaticMappingService.class);
		for (var node : ctx.getSelection()) {
			if (node instanceof UnitSliceNode<?> un) {
				un.descendActualDefinitions(ms);
				un.setExpanded(true);
			}
		}
		model.reload();
	}

	private boolean enableFindActualInputs(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof UnitSliceNode && n.displaySnap());
	}

	private void activateFindActualInputs(SliceActionContext ctx) {
		for (var node : ctx.getSelection()) {
			if (node instanceof UnitSliceNode<?> un) {
				un.descendActualInputs();
				un.setExpanded(true);
			}
		}
		model.reload();
	}

	private boolean enableFindActualConditionalBranchTo(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof InstructionSliceNode && n.displaySnap());
	}

	private void activateFindActualConditionalBranchTo(SliceActionContext ctx) {
		new TaskLauncher(new Task("Find Dynamic Execution Dependency") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof InstructionSliceNode in) {
						in.descendActualConditionalBranchTo(monitor,
							tool.getService(DebuggerStaticMappingService.class));
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}

	private boolean enableFindStaticDefinitions(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(n -> n instanceof UnitSliceNode u && u.getStaticPc() != null);
	}

	private void activateFindStaticDefinitions(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		new TaskLauncher(new Task("Find Static Value Definitions") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof UnitSliceNode<?> un) {
						un.descendStaticDefinitions(ms, monitor);
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}

	private boolean enableFindStaticInputs(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(
					n -> n instanceof InstructionSliceNode i && i.getStaticPc() != null);
	}

	private void activateFindStaticInputs(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		for (var node : ctx.getSelection()) {
			if (node instanceof InstructionSliceNode in) {
				in.descendStaticInputs(ms);
				in.setExpanded(true);
			}
		}
		model.reload();
	}

	private boolean enableFindStaticConditionalBranchTo(SliceActionContext ctx) {
		return ctx.getSelection()
				.stream()
				.anyMatch(
					n -> n instanceof InstructionSliceNode i && i.getStaticPc() != null);
	}

	private void activateFindStaticConditionalBranchTo(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}
		new TaskLauncher(new Task("Find Static Execution Dependencies") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof InstructionSliceNode in) {
						in.descendStaticConditionalBranchTo(ms, monitor);
					}
				}
				Swing.runLater(() -> model.reload());
			}
		});
	}

	private boolean enableSearch(SliceActionContext ctx) {
		return true;
	}

	record NodePath(List<UnitSliceNode<?>> path) {
		public static NodePath of(UnitSliceNode<?>... path) {
			return new NodePath(Arrays.asList(path));
		}

		public NodePath(List<UnitSliceNode<?>> path) {
			this.path = List.copyOf(path);
		}

		public UnitSliceNode<?> last() {
			return path.getLast();
		}

		public NodePath append(UnitSliceNode<?> node) {
			return new NodePath(Stream.concat(path.stream(), Stream.of(node)).toList());
		}

		public int size() {
			return path.size();
		}
	}

	private void activateSearch(SliceActionContext ctx) {
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return;
		}

		// Show dialog to get user-controlled criteria before launching task
		BfsParametersDialog dialog = new BfsParametersDialog();
		dialog.show(tool);
		if (!dialog.isValid()) {
			return;
		}

		final String regex = dialog.getRegex();
		final int maxHops = dialog.getMaxHops();
		final long minSnapshot = dialog.getMinSnapshot();

		// TODO: Consider user selection, but that could get hairy among the trace and mapped images.
		//    I don't know what plugin, if any, tracks selection per program.
		//    Not too hard to track events, though.
		Predicate<UnitSliceNode<?>> criteria = n -> {
			return n.unit.toString().matches(regex) || n.getLocation().matches(regex);
		};

		new TaskLauncher(new Task("Search", true, true, false, false) {
			Set<UnitSliceNode<?>> visited = new HashSet<>();
			SequencedSet<NodePath> queue = new LinkedHashSet<>();
			List<NodePath> found = new ArrayList<>();

			int count;
			int max;

			private void consider(NodePath path, TaskMonitor monitor) {
				UnitSliceNode<?> lastNode = path.last();

				if (!visited.add(path.last())) {
					return;
				}

				// Check if this node matches our criteria
				if (criteria.test(lastNode)) {
					found.add(path);
					monitor.setMessage("Found %d".formatted(found.size()));
				}
				// Check if node is before minimum snapshot
				else if (lastNode.snap < minSnapshot) {
					return; // Don't queue or count this node
				}
				// Check if we've exceeded maximum hops
				else if (path.size() > maxHops) {
					return; // Don't queue or count this node
				}
				else {
					queue.add(path);
					max++;
				}
			}

			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (var node : ctx.getSelection()) {
					if (node instanceof UnitSliceNode<?> un) {
						// Initial nodes will be checked in consider() method
						queue.add(NodePath.of(un));
					}
				}
				count = 0;
				max = queue.size();

				try {
					while (!queue.isEmpty()) {
						monitor.checkCancelled();
						NodePath next = queue.removeFirst();
						count++;
						monitor.setMaximum(max);
						monitor.setProgress(count);
						switch (next.last()) {
							case InstructionSliceNode in -> {
								InstructionSliceNode branchTo =
									in.computeActualConditionalBranchTo(monitor, ms);
								if (branchTo != null) {
									consider(next.append(branchTo), monitor);
								}
								for (InstructionSliceNode definition : in
										.computeActualDefinitions(ms)) {
									consider(next.append(definition), monitor);
								}
								for (DataSliceNode input : in.computeActualInputs()) {
									consider(next.append(input), monitor);
								}
							}
							case DataSliceNode dn -> {
								for (InstructionSliceNode definition : dn
										.computeActualDefinitions(ms)) {
									consider(next.append(definition), monitor);
								}

								// Unlikely.... Why?
								for (DataSliceNode input : dn.computeActualInputs()) {
									consider(next.append(input), monitor);
								}
							}
							default -> throw new AssertionError();
						}
					}
				}
				catch (CancelledException e) {
					// Fine. Let's populate with what we found anyway
				}
				Swing.runLater(this::addNodes);
			}

			void addNodes() {
				List<AbstractSliceNode> sel = new ArrayList<>();
				for (NodePath f : found) {
					/**
					 * This first of each path would be a seed of the search, and so must already be
					 * in the tree model. Iterate starting at 1, adding each to its parent.
					 */
					sel.add(f.last());
					for (int i = 1; i < f.path.size(); i++) {
						var node = f.path.get(i);
						var parent = f.path.get(i - 1);
						if (!parent.getChildren().contains(node)) {
							parent.add(node);
							parent.setExpanded(true);
						}
					}
				}
				model.reload();
				table.getFilterPanel().setSelectedItems(sel);
			}
		});
	}
}
