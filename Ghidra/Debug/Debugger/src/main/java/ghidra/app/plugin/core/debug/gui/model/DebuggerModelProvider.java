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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.*;
import java.awt.event.*;
import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.*;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.MultiProviderSaveBehavior.SaveableProvider;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ObjectRow;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.ObjectTreeModel.AbstractNode;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.AutoConfigState;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.*;
import ghidra.util.Msg;

public class DebuggerModelProvider extends ComponentProvider implements SaveableProvider {

	private static final AutoConfigState.ClassHandler<DebuggerModelProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerModelProvider.class, MethodHandles.lookup());
	private static final String KEY_DEBUGGER_COORDINATES = "DebuggerCoordinates";
	private static final String KEY_PATH = "Path";

	private final DebuggerModelPlugin plugin;
	private final boolean isClone;

	private JPanel mainPanel = new JPanel(new BorderLayout());

	protected JTextField pathField;
	protected JButton goButton;
	protected ObjectsTreePanel objectsTreePanel;
	protected ObjectsTablePanel elementsTablePanel;
	protected PathsTablePanel attributesTablePanel;

	/*testing*/ DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	/*testing*/ TraceObjectKeyPath path = TraceObjectKeyPath.of();

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined(
		description = "Text color for values that have just changed",
		name = DebuggerResources.OPTION_NAME_COLORS_VALUE_CHANGED,
		help = @HelpInfo(anchor = "colors"))
	private Color diffColor = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED;

	@AutoOptionDefined(
		description = "Select text color for values that have just changed",
		name = DebuggerResources.OPTION_NAME_COLORS_VALUE_CHANGED_SEL,
		help = @HelpInfo(anchor = "colors"))
	private Color diffColorSel = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED_SEL;

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	@AutoConfigStateField
	private boolean limitToSnap = false;
	@AutoConfigStateField
	private boolean showHidden = false;
	@AutoConfigStateField
	private boolean showPrimitivesInTree = false;
	@AutoConfigStateField
	private boolean showMethodsInTree = false;

	DockingAction actionCloneWindow;
	ToggleDockingAction actionLimitToCurrentSnap;
	ToggleDockingAction actionShowHidden;
	ToggleDockingAction actionShowPrimitivesInTree;
	ToggleDockingAction actionShowMethodsInTree;
	DockingAction actionFollowLink;
	// TODO: Remove stopgap
	DockingAction actionStepBackward;
	DockingAction actionStepForward;

	DebuggerObjectActionContext myActionContext;

	public DebuggerModelProvider(DebuggerModelPlugin plugin, boolean isClone) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_MODEL, plugin.getName());
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		this.autoOptionsWiring = AutoOptions.wireOptions(plugin, this);
		this.plugin = plugin;
		this.isClone = isClone;

		setIcon(DebuggerResources.ICON_PROVIDER_MODEL);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_MODEL);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.LEFT);
		createActions();

		if (isClone) {
			setTitle("[" + DebuggerResources.TITLE_PROVIDER_MODEL + "]");
			setWindowGroup("Debugger.Core.disconnected");
			setIntraGroupPosition(WindowPosition.STACK);
			mainPanel.setBorder(BorderFactory.createLineBorder(Color.ORANGE, 2));
			setTransient();
		}
		else {
			setTitle(DebuggerResources.TITLE_PROVIDER_MODEL);
			setWindowGroup("Debugger.Core");
		}

		doSetLimitToCurrentSnap(limitToSnap);

		setVisible(true);
		contextChanged();
	}

	@Override
	public void removeFromTool() {
		plugin.providerRemoved(this);
		super.removeFromTool();
	}

	protected void buildMainPanel() {
		pathField = new JTextField();
		pathField.setInputVerifier(new InputVerifier() {
			@Override
			public boolean verify(JComponent input) {
				try {
					setPath(TraceObjectKeyPath.parse(pathField.getText()), pathField);
					return true;
				}
				catch (IllegalArgumentException e) {
					plugin.getTool().setStatusInfo("Invalid Path: " + pathField.getText(), true);
					return false;
				}
			}
		});
		goButton = new JButton("Go");
		ActionListener gotoPath = evt -> {
			try {
				setPath(TraceObjectKeyPath.parse(pathField.getText()), pathField);
				KeyboardFocusManager.getCurrentKeyboardFocusManager().clearGlobalFocusOwner();
			}
			catch (IllegalArgumentException e) {
				Msg.showError(this, mainPanel, DebuggerResources.TITLE_PROVIDER_MODEL,
					"Invalid Query: " + pathField.getText());
			}
		};
		goButton.addActionListener(gotoPath);
		pathField.addActionListener(gotoPath);
		pathField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					pathField.setText(path.toString());
					KeyboardFocusManager.getCurrentKeyboardFocusManager().clearGlobalFocusOwner();
				}
			}
		});

		objectsTreePanel = new ObjectsTreePanel();
		elementsTablePanel = new ObjectsTablePanel(plugin);
		attributesTablePanel = new PathsTablePanel(plugin);

		JSplitPane lrSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		lrSplit.setResizeWeight(0.2);
		JSplitPane tbSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		tbSplit.setResizeWeight(0.7);
		lrSplit.setRightComponent(tbSplit);

		JPanel queryPanel = new JPanel(new BorderLayout());

		queryPanel.add(new JLabel("Path: "), BorderLayout.WEST);
		queryPanel.add(pathField, BorderLayout.CENTER);
		queryPanel.add(goButton, BorderLayout.EAST);

		JPanel labeledElementsTablePanel = new JPanel(new BorderLayout());
		labeledElementsTablePanel.add(elementsTablePanel);
		labeledElementsTablePanel.add(new JLabel("Elements"), BorderLayout.NORTH);

		JPanel labeledAttributesTablePanel = new JPanel(new BorderLayout());
		labeledAttributesTablePanel.add(attributesTablePanel);
		labeledAttributesTablePanel.add(new JLabel("Attributes"), BorderLayout.NORTH);

		lrSplit.setLeftComponent(objectsTreePanel);
		tbSplit.setLeftComponent(labeledElementsTablePanel);
		tbSplit.setRightComponent(labeledAttributesTablePanel);

		mainPanel.add(queryPanel, BorderLayout.NORTH);
		mainPanel.add(lrSplit, BorderLayout.CENTER);

		objectsTreePanel.addTreeSelectionListener(evt -> {
			Trace trace = current.getTrace();
			if (trace == null) {
				return;
			}
			if (trace.getObjectManager().getRootObject() == null) {
				return;
			}
			List<AbstractNode> sel = objectsTreePanel.getSelectedItems();
			if (!sel.isEmpty()) {
				myActionContext = new DebuggerObjectActionContext(sel.stream()
						.map(n -> n.getValue())
						.collect(Collectors.toList()),
					this, objectsTreePanel);
			}
			else {
				myActionContext = null;
			}
			contextChanged();

			if (sel.size() != 1) {
				// TODO: Multiple paths? PathMatcher can do it, just have to parse
				// Just leave whatever was there.
				return;
			}
			TraceObjectValue value = sel.get(0).getValue();
			TraceObject parent = value.getParent();
			TraceObjectKeyPath path;
			if (parent == null) {
				path = TraceObjectKeyPath.of();
			}
			else {
				path = parent.getCanonicalPath().key(value.getEntryKey());
			}
			setPath(path, objectsTreePanel);
		});
		elementsTablePanel.addSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			List<ValueRow> sel = elementsTablePanel.getSelectedItems();
			if (!sel.isEmpty()) {
				myActionContext = new DebuggerObjectActionContext(sel.stream()
						.map(r -> r.getValue())
						.collect(Collectors.toList()),
					this, elementsTablePanel);
			}
			else {
				myActionContext = null;
			}
			contextChanged();

			if (sel.size() != 1) {
				attributesTablePanel.setQuery(ModelQuery.attributesOf(path));
				return;
			}
			TraceObjectValue value = sel.get(0).getValue();
			if (!value.isObject()) {
				return;
			}
			attributesTablePanel
					.setQuery(ModelQuery.attributesOf(value.getChild().getCanonicalPath()));
		});
		attributesTablePanel.addSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			List<PathRow> sel = attributesTablePanel.getSelectedItems();
			if (!sel.isEmpty()) {
				myActionContext = new DebuggerObjectActionContext(sel.stream()
						.map(r -> Objects.requireNonNull(r.getPath().getLastEntry()))
						.collect(Collectors.toList()),
					this, attributesTablePanel);
			}
			else {
				myActionContext = null;
			}
			contextChanged();
		});

		elementsTablePanel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2 || e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				activatedElementsTable();
			}
		});
		elementsTablePanel.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					return;
				}
				activatedElementsTable();
				e.consume();
			}
		});
		attributesTablePanel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2 || e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				activatedAttributesTable();
			}
		});
		attributesTablePanel.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					return;
				}
				activatedAttributesTable();
				e.consume();
			}
		});
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext != null) {
			return myActionContext;
		}
		return super.getActionContext(event);
	}

	protected void createActions() {
		actionCloneWindow = CloneWindowAction.builder(plugin)
				.enabledWhen(c -> current.getTrace() != null)
				.onAction(c -> activatedCloneWindow())
				.buildAndInstallLocal(this);
		actionLimitToCurrentSnap = LimitToCurrentSnapAction.builder(plugin)
				.onAction(this::toggledLimitToCurrentSnap)
				.buildAndInstallLocal(this);
		actionShowHidden = ShowHiddenAction.builder(plugin)
				.onAction(this::toggledShowHidden)
				.buildAndInstallLocal(this);
		actionShowPrimitivesInTree = ShowPrimitivesInTreeAction.builder(plugin)
				.onAction(this::toggledShowPrimitivesInTree)
				.buildAndInstallLocal(this);
		actionShowMethodsInTree = ShowMethodsInTreeAction.builder(plugin)
				.onAction(this::toggledShowMethodsInTree)
				.buildAndInstallLocal(this);
		actionFollowLink = FollowLinkAction.builder(plugin)
				.withContext(DebuggerObjectActionContext.class)
				.enabledWhen(this::hasSingleLink)
				.onAction(this::activatedFollowLink)
				.buildAndInstallLocal(this);

		// TODO: These are a stopgap until the plot column header provides nav
		actionStepBackward = StepSnapBackwardAction.builder(plugin)
				.enabledWhen(this::isStepBackwardEnabled)
				.onAction(this::activatedStepBackward)
				.buildAndInstallLocal(this);
		actionStepForward = StepSnapForwardAction.builder(plugin)
				.enabledWhen(this::isStepForwardEnabled)
				.onAction(this::activatedStepForward)
				.buildAndInstallLocal(this);
	}

	private void activatedElementsTable() {
		ValueRow row = elementsTablePanel.getSelectedItem();
		if (row == null) {
			return;
		}
		if (!(row instanceof ObjectRow)) {
			return;
		}
		ObjectRow objectRow = (ObjectRow) row;
		setPath(objectRow.getTraceObject().getCanonicalPath());
	}

	private void activatedAttributesTable() {
		PathRow row = attributesTablePanel.getSelectedItem();
		if (row == null) {
			return;
		}
		Object value = row.getValue();
		if (!(value instanceof TraceObject)) {
			return;
		}
		TraceObject object = (TraceObject) value;
		setPath(object.getCanonicalPath());
	}

	private void activatedCloneWindow() {
		DebuggerModelProvider clone = plugin.createDisconnectedProvider();
		SaveState configState = new SaveState();
		this.writeConfigState(configState);
		clone.readConfigState(configState);
		SaveState dataState = new SaveState();
		this.writeDataState(dataState);
		// coords are omitted by main window
		// also, cannot save unless trace is in a project
		clone.coordinatesActivated(current);
		clone.readDataState(dataState);
		plugin.getTool().showComponentProvider(clone, true);
	}

	private void toggledLimitToCurrentSnap(ActionContext ctx) {
		setLimitToCurrentSnap(actionLimitToCurrentSnap.isSelected());
	}

	private void toggledShowHidden(ActionContext ctx) {
		setShowHidden(actionShowHidden.isSelected());
	}

	private void toggledShowPrimitivesInTree(ActionContext ctx) {
		setShowPrimitivesInTree(actionShowPrimitivesInTree.isSelected());
	}

	private void toggledShowMethodsInTree(ActionContext ctx) {
		setShowMethodsInTree(actionShowMethodsInTree.isSelected());
	}

	private boolean hasSingleLink(DebuggerObjectActionContext ctx) {
		List<TraceObjectValue> values = ctx.getObjectValues();
		if (values.size() != 1) {
			return false;
		}
		TraceObjectValue val = values.get(0);
		if (val.isCanonical() || !val.isObject()) {
			return false;
		}
		return true;
	}

	private void activatedFollowLink(DebuggerObjectActionContext ctx) {
		List<TraceObjectValue> values = ctx.getObjectValues();
		if (values.size() != 1) {
			return;
		}
		setPath(values.get(0).getChild().getCanonicalPath(), null);
	}

	private boolean isStepBackwardEnabled(ActionContext ignored) {
		if (current.getTrace() == null) {
			return false;
		}
		if (!current.getTime().isSnapOnly()) {
			return true;
		}
		if (current.getSnap() <= 0) {
			return false;
		}
		return true;
	}

	private void activatedStepBackward(ActionContext ignored) {
		if (current.getTime().isSnapOnly()) {
			traceManager.activateSnap(current.getSnap() - 1);
		}
		else {
			traceManager.activateSnap(current.getSnap());
		}
	}

	private boolean isStepForwardEnabled(ActionContext ignored) {
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return false;
		}
		Long maxSnap = curTrace.getTimeManager().getMaxSnap();
		if (maxSnap == null || current.getSnap() >= maxSnap) {
			return false;
		}
		return true;
	}

	private void activatedStepForward(ActionContext ignored) {
		traceManager.activateSnap(current.getSnap() + 1);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void coordinatesActivated(DebuggerCoordinates coords) {
		this.current = coords;
		objectsTreePanel.goToCoordinates(coords);
		elementsTablePanel.goToCoordinates(coords);
		attributesTablePanel.goToCoordinates(coords);

		checkPath();
	}

	public void traceClosed(Trace trace) {
		if (current.getTrace() == trace) {
			coordinatesActivated(DebuggerCoordinates.NOWHERE);
		}
	}

	protected void setPath(TraceObjectKeyPath path, JComponent source) {
		if (Objects.equals(this.path, path)) {
			return;
		}
		this.path = path;
		if (source != pathField) {
			pathField.setText(path.toString());
		}
		if (source != objectsTreePanel) {
			selectInTree(path);
		}
		elementsTablePanel.setQuery(ModelQuery.elementsOf(path));
		attributesTablePanel.setQuery(ModelQuery.attributesOf(path));

		checkPath();
	}

	protected void checkPath() {
		if (objectsTreePanel.getNode(path) == null) {
			plugin.getTool().setStatusInfo("No such object at path " + path, true);
		}
	}

	public void setPath(TraceObjectKeyPath path) {
		setPath(path, null);
	}

	public TraceObjectKeyPath getPath() {
		return path;
	}

	protected void doSetLimitToCurrentSnap(boolean limitToSnap) {
		this.limitToSnap = limitToSnap;
		actionLimitToCurrentSnap.setSelected(limitToSnap);
		objectsTreePanel.setLimitToSnap(limitToSnap);
		elementsTablePanel.setLimitToSnap(limitToSnap);
		attributesTablePanel.setLimitToSnap(limitToSnap);
	}

	public void setLimitToCurrentSnap(boolean limitToSnap) {
		if (this.limitToSnap == limitToSnap) {
			return;
		}
		doSetLimitToCurrentSnap(limitToSnap);
	}

	public boolean isLimitToCurrentSnap() {
		return limitToSnap;
	}

	protected void doSetShowHidden(boolean showHidden) {
		this.showHidden = showHidden;
		actionShowHidden.setSelected(showHidden);
		objectsTreePanel.setShowHidden(showHidden);
		elementsTablePanel.setShowHidden(showHidden);
		attributesTablePanel.setShowHidden(showHidden);
	}

	public void setShowHidden(boolean showHidden) {
		if (this.showHidden == showHidden) {
			return;
		}
		doSetShowHidden(showHidden);
	}

	public boolean isShowHidden() {
		return showHidden;
	}

	protected void doSetShowPrimitivesInTree(boolean showPrimitivesInTree) {
		this.showPrimitivesInTree = showPrimitivesInTree;
		actionShowPrimitivesInTree.setSelected(showPrimitivesInTree);
		objectsTreePanel.setShowPrimitives(showPrimitivesInTree);
	}

	public void setShowPrimitivesInTree(boolean showPrimitivesInTree) {
		if (this.showPrimitivesInTree == showPrimitivesInTree) {
			return;
		}
		doSetShowPrimitivesInTree(showPrimitivesInTree);
	}

	public boolean isShowPrimitivesInTree() {
		return showPrimitivesInTree;
	}

	protected void doSetShowMethodsInTree(boolean showMethodsInTree) {
		this.showMethodsInTree = showMethodsInTree;
		actionShowMethodsInTree.setSelected(showMethodsInTree);
		objectsTreePanel.setShowMethods(showMethodsInTree);
	}

	public void setShowMethodsInTree(boolean showMethodsInTree) {
		if (this.showMethodsInTree == showMethodsInTree) {
			return;
		}
		doSetShowMethodsInTree(showMethodsInTree);
	}

	public boolean isShowMethodsInTree() {
		return showMethodsInTree;
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_VALUE_CHANGED)
	public void setDiffColor(Color diffColor) {
		if (Objects.equals(this.diffColor, diffColor)) {
			return;
		}
		this.diffColor = diffColor;
		objectsTreePanel.setDiffColor(diffColor);
		elementsTablePanel.setDiffColor(diffColor);
		attributesTablePanel.setDiffColor(diffColor);
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_VALUE_CHANGED_SEL)
	public void setDiffColorSel(Color diffColorSel) {
		if (Objects.equals(this.diffColorSel, diffColorSel)) {
			return;
		}
		this.diffColorSel = diffColorSel;
		objectsTreePanel.setDiffColorSel(diffColorSel);
		elementsTablePanel.setDiffColorSel(diffColorSel);
		attributesTablePanel.setDiffColorSel(diffColorSel);
	}

	protected void selectInTree(TraceObjectKeyPath path) {
		objectsTreePanel.setSelectedKeyPaths(List.of(path));
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		doSetLimitToCurrentSnap(limitToSnap);
		doSetShowHidden(showHidden);
		doSetShowPrimitivesInTree(showPrimitivesInTree);
		doSetShowMethodsInTree(showMethodsInTree);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (isClone) {
			current.writeDataState(plugin.getTool(), saveState, KEY_DEBUGGER_COORDINATES);
		}
		saveState.putString(KEY_PATH, path.toString());
		// TODO?
		//GTreeState treeState = objectsTreePanel.tree.getTreeState();
	}

	@Override
	public void readDataState(SaveState saveState) {
		if (isClone) {
			DebuggerCoordinates coords = DebuggerCoordinates.readDataState(plugin.getTool(),
				saveState, KEY_DEBUGGER_COORDINATES, true);
			if (coords != DebuggerCoordinates.NOWHERE) {
				coordinatesActivated(coords);
			}
		}
		setPath(TraceObjectKeyPath.parse(saveState.getString(KEY_PATH, "")));
	}
}
