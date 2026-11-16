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

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.widgets.gtreetable.GTreeTable;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractSliceProvider extends ComponentProviderAdapter {
	protected final DebuggerTraceSlicePlugin plugin;
	protected final JPanel panel = new JPanel(new BorderLayout());
	protected final SliceModel model;
	protected final GTreeTable<AbstractSliceNode> table;

	public AbstractSliceProvider(DebuggerTraceSlicePlugin plugin, String title, Trace trace,
			CodeUnit unit, long snap) {
		this(plugin, title, trace, unit, snap, true);
	}

	AbstractSliceProvider(DebuggerTraceSlicePlugin plugin, String title, Trace trace,
			CodeUnit unit, long snap, boolean addSeed) {
		this.plugin = plugin;
		super(plugin.getTool(), title, plugin.getName());
		setTransient();
		tool.addComponentProvider(this, false);

		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		ProgramLocation staticPc = SliceAnalysis.INSTANCE.computeStaticPc(trace, snap, ms);
		this.model = new SliceModel(trace, staticPc == null ? null : staticPc.getProgram(),
			staticPc == null ? null : staticPc.getByteAddress());
		if (addSeed) {
			RootSliceNode root = this.model.getRoot();
			root.add(root.newUnitNode(SliceEdgeType.SEED, unit, snap, true, ms));
		}
		this.table = new GTreeTable<>(model);

		populateComponents();
		createActions();
		createSaveAction();

		table.getTable().addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					gotoSelected();
				}
			}
		});
		// TODO: Keyboard ENTER, too
	}

	void dispose() {
		model.dispose();
	}

	void populateComponents() {
		panel.add(table);
	}

	private void createSaveAction() {
		new ActionBuilder("Save", plugin.getName())
				.description("Save this slice session as JSON")
				.toolBarGroup("Slice")
				.toolBarIcon(DebuggerResources.ICON_SAVE)
				.onAction(_ -> plugin.saveSession(this))
				.buildAndInstallLocal(this);
	}

	Trace getTrace() {
		return model.getRoot().trace;
	}

	List<AbstractSliceNode> restoreNodes(List<SliceSession.Node> nodes, TaskMonitor monitor)
			throws IOException, CancelledException {
		RootSliceNode root = model.getRoot();
		List<AbstractSliceNode> restored = new ArrayList<>();
		for (SliceSession.Node saved : nodes) {
			monitor.checkCancelled();
			restored.add(SliceSession.restoreNode(root, root.trace, saved, tool, monitor));
		}
		return restored;
	}

	void addRestoredNodes(List<AbstractSliceNode> nodes) {
		RootSliceNode root = model.getRoot();
		for (AbstractSliceNode node : nodes) {
			root.add(node);
		}
		model.reload();
	}

	List<SliceSession.Node> saveNodes() {
		return model.getRoot()
				.getChildren()
				.stream()
				.map(n -> SliceSession.saveNode((AbstractSliceNode) n))
				.toList();
	}

	abstract SliceDirection getDirection();

	protected void createActions() {
		String owner = plugin.getName();
		new ActionBuilder("Examine Slice Path", owner)
				.popupMenuPath("Examine Path...")
				.popupMenuGroup("Search")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableExaminePath)
				.onAction(this::activateExaminePath)
				.buildAndInstallLocal(this);
		new ActionBuilder("Remove Slice Node", owner)
				.popupMenuPath("Remove")
				.popupMenuGroup("Edit")
				.description("Remove node and its descendants")
				.withContext(SliceActionContext.class)
				.enabledWhen(this::enableRemoveNode)
				.onAction(this::removeNode)
				.buildAndInstallLocal(this);
	}

	private boolean enableRemoveNode(SliceActionContext ctx) {
		return ctx.getSelection().size() == 1 && ctx.getSelection().getFirst().getParent() != null;
	}

	private void removeNode(SliceActionContext ctx) {
		if (!enableRemoveNode(ctx)) {
			return;
		}
		AbstractSliceNode node = ctx.getSelection().getFirst();
		var parent = node.getParent();
		parent.remove(node);
		model.reload();
	}

	/**
	 * Creates the "Examine Path" action that allows users to view the path from root/seed node to
	 * the selected node in a table format.
	 */
	protected void createExaminePathAction() {
	}

	private boolean enableExaminePath(SliceActionContext ctx) {
		return ctx.getSelection().size() == 1;
	}

	private void activateExaminePath(SliceActionContext ctx) {
		List<AbstractSliceNode> selection = ctx.getSelection();
		if (selection.size() != 1) {
			return;
		}
		if (!(selection.get(0) instanceof UnitSliceNode<?> selected)) {
			return;
		}

		// Build path from root to selected node
		List<UnitSliceNode<?>> path = new ArrayList<>();
		UnitSliceNode<?> current = selected;
		while (current != null) {
			path.add(current);
			if (current.getParent() instanceof UnitSliceNode<?> parent) {
				current = parent;
			}
			else {
				break;
			}
		}

		// Convert to PathRow objects for display
		List<PathRow> rows = new ArrayList<>();
		for (UnitSliceNode<?> node : path) {
			long snap = node.getSnap();
			String location = node.getLocation();
			Address address = node.getAddress();
			CodeUnit codeUnit = node.unit;
			rows.add(new PathRow(snap, location, address, codeUnit));
		}

		// Show the path examining provider
		PathProvider provider = new PathProvider(plugin, rows);
		tool.showComponentProvider(provider, true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void show() {
		tool.showComponentProvider(this, true);
	}

	void gotoSelected() {
		AbstractSliceNode node = table.getFilterPanel().getSelectedItem();
		if (node == null) {
			return;
		}
		long snap = node.getSnap();
		Address address = node.getAddress();
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		traceManager.activateSnap(snap);
		DebuggerListingService listingService = tool.getService(DebuggerListingService.class);
		if (address != null && !address.isRegisterAddress()) {
			listingService.goTo(address, true);
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new SliceActionContext(table.getFilterPanel().getSelectedItems());
	}
}
