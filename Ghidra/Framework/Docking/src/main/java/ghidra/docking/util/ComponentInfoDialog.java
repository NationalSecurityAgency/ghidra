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
package ghidra.docking.util;

import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import java.util.List;

import javax.accessibility.AccessibleContext;
import javax.swing.*;

import docking.*;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.table.*;
import generic.theme.GThemeDefaults.Ids.Fonts;
import generic.theme.Gui;
import generic.util.WindowUtilities;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.bean.GGlassPane;
import ghidra.util.layout.PairLayout;
import resources.Icons;

/**
 * Diagnostic dialog for display information about the components in a window and related focus
 * information.
 */
public class ComponentInfoDialog extends DialogComponentProvider implements PropertyChangeListener {
	private static final String ACTION_OWNER = "Component Info";
	private Container rootComponentForTable;
	private List<ComponentInfo> infos = new ArrayList<>();
	private Map<Component, ComponentInfo> infoMap = new HashMap<>();

	private GFilterTable<ComponentInfo> filterTable;
	private ComponentTableModel model;
	private ToggleDockingAction filterAction;
	private JTextField oldWindowTextField;
	private JTextField newWindowTextField;
	private JTextField oldProviderTextField;
	private JTextField newProviderTextField;
	private JTextField oldComponentTextField;
	private JTextField newComponentTextField;
	private Window currentWindow;
	private ComponentProvider currentProvider;
	private Component currentComponent;
	private EventDisplayPanel eventDisplay;
	private JSplitPane splitPane;
	private ToggleDockingAction eventAction;
	private ToggleDockingAction toggleFollowFocusAction;
	private boolean updateOnFocusChange = true;

	public ComponentInfoDialog() {
		super("Component Inspector", false);

		addWorkPanel(buildMainPanel());
		addDismissButton();
		addOKButton();
		setOkButtonText("Reset");
		setOkToolTip("Clears component table and will re-populate on next focussed component");

		setPreferredSize(1200, 600);
		eventDisplay = new EventDisplayPanel();
		createActions();

		KeyboardFocusManager km = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		km.addPropertyChangeListener("permanentFocusOwner", this);
		reset();
	}

	private void createActions() {
		// we don't automatically refresh the list of components in a window if it changes
		DockingAction refreshAction = new ActionBuilder("Refresh", ACTION_OWNER)
				.toolBarIcon(Icons.REFRESH_ICON)
				.onAction(c -> refreshModelData())
				.build();
		addAction(refreshAction);

		// this action also just calls the refreshModelData() method, but since it is a toggle
		// action, the refresh model data will rebuild with the filter option toggled.
		filterAction = new ToggleActionBuilder("Filter", ACTION_OWNER)
				.toolBarIcon(Icons.CONFIGURE_FILTER_ICON)
				.description("Filters out most non-focusable components")
				.onAction(c -> refreshModelData())
				.selected(true)
				.build();
		addAction(filterAction);

		eventAction = new ToggleActionBuilder("Show Events", ACTION_OWNER)
				.toolBarIcon(Icons.INFO_ICON)
				.description("Shows focus events")
				.onAction(c -> toggleShowEvents())
				.build();
		addAction(eventAction);

		toggleFollowFocusAction = new ToggleActionBuilder("Follow Focus", ACTION_OWNER)
				.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
				.description("On causes component table to constant repopulate as focus changes")
				.onAction(c -> toggleFollowFocus())
				.selected(true)
				.build();
		addAction(toggleFollowFocusAction);
	}

	private void toggleFollowFocus() {
		updateOnFocusChange = toggleFollowFocusAction.isSelected();
		setOkEnabled(!updateOnFocusChange);
	}

	private void toggleShowEvents() {
		if (eventAction.isSelected()) {
			splitPane.setBottomComponent(eventDisplay);
			splitPane.setDividerLocation(0.7);
			splitPane.setResizeWeight(0.7);
		}
		else {
			splitPane.setBottomComponent(null);
		}
	}

	private void refreshModelData() {
		buildComponentModel();
	}

	@Override
	protected void okCallback() {
		reset();
	}

	// clear the current table data. The next component to get focus will repopulate the table data.
	private void reset() {
		setRootContainer(null);
	}

	private ComponentInfo getComponentInfo(Component comp) {
		return infoMap.get(comp);
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildCenterPanel(), BorderLayout.CENTER);
		panel.add(buildInfoPanel(), BorderLayout.SOUTH);
		return panel;

	}

	private JComponent buildCenterPanel() {
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		splitPane.setTopComponent(buildTablePanel());
		return splitPane;
	}

	private JComponent buildTablePanel() {
		model = new ComponentTableModel();
		filterTable = new GFilterTable<ComponentInfo>(model);
		filterTable.setAccessibleNamePrefix("Component Info");
		return filterTable;
	}

	private JComponent buildInfoPanel() {
		JPanel panel = new JPanel(new PairLayout(4, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(4, 10, 20, 10));
		oldWindowTextField = new JTextField(50);
		newWindowTextField = new JTextField(50);
		oldProviderTextField = new JTextField(50);
		newProviderTextField = new JTextField(50);
		oldComponentTextField = new JTextField(50);
		newComponentTextField = new JTextField(50);
		oldWindowTextField.setFocusable(false);
		newWindowTextField.setFocusable(false);
		oldProviderTextField.setFocusable(false);
		newProviderTextField.setFocusable(false);
		oldComponentTextField.setFocusable(false);
		newComponentTextField.setFocusable(false);
		panel.add(new JLabel("Focused Window (new/old): ", SwingConstants.RIGHT));
		panel.add(buildTextPair(newWindowTextField, oldWindowTextField));
		panel.add(new JLabel("Focused Provider (new/old): ", SwingConstants.RIGHT));
		panel.add(buildTextPair(newProviderTextField, oldProviderTextField));
		panel.add(new JLabel("Focused Component (new/old): ", SwingConstants.RIGHT));
		panel.add(buildTextPair(newComponentTextField, oldComponentTextField));
		return panel;
	}

	private Component buildTextPair(JComponent comp1, JComponent comp2) {
		JPanel panel = new JPanel(new GridLayout(1, 2, 10, 10));
		panel.add(comp1);
		panel.add(comp2);
		return panel;
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		eventDisplay.report(getDisplayString(evt));
		filterTable.setSelectedRowObject(null);
		Component newFocusComponent = (Component) evt.getNewValue();
		selectFocusedComponentInTable(newFocusComponent);
		updateFocusInfo(newFocusComponent);

	}

	private String getDisplayString(PropertyChangeEvent evt) {
		StringBuilder builder = new StringBuilder();
		builder.append(evt.getPropertyName());
		builder.append(": OLD = ");
		builder.append(getName((Component) evt.getOldValue()));
		builder.append(", NEW = ");
		builder.append(getName((Component) evt.getNewValue()));
		return builder.toString();
	}

	private void updateFocusInfo(Component newFocusComponent) {
		if (newFocusComponent == null) {
			return;
		}
		if (newFocusComponent == currentComponent) {
			return;
		}
		oldComponentTextField.setText(newComponentTextField.getText());
		currentComponent = newFocusComponent;
		newComponentTextField.setText(getName(currentComponent));

		oldProviderTextField.setText(newProviderTextField.getText());
		currentProvider = DockingWindowManager.getActiveInstance()
				.getProvider(newFocusComponent);
		newProviderTextField.setText(currentProvider == null ? "" : currentProvider.getName());

		oldWindowTextField.setText(newWindowTextField.getText());
		currentWindow = SwingUtilities.windowForComponent(newFocusComponent);
		newWindowTextField.setText(WindowUtilities.getTitle(currentWindow));

	}

	private String getName(Component comp) {
		if (comp == null) {
			return null;
		}
		String name = comp.getName();
		StringBuilder buf = new StringBuilder(name == null ? "" : name);
		buf.append(" (");
		buf.append(comp.getClass()
				.getSimpleName());
		buf.append(")");
		return buf.toString();
	}

	private void selectFocusedComponentInTable(Component newFocusComponent) {
		if (infos.isEmpty() || updateOnFocusChange) {
			if (newFocusComponent == null) {
				return;
			}
			setRootContainer(findRoot(newFocusComponent));
		}
		ComponentInfo focusedInfo = getComponentInfo(newFocusComponent);
		filterTable.setSelectedRowObject(focusedInfo);
	}

	void setRootContainer(Container container) {
		if (rootComponentForTable == container) {
			return;
		}
		rootComponentForTable = container;
		buildComponentModel();
	}

	void buildComponentModel() {
		ComponentInfo.resetIds();
		infos = findComponents(rootComponentForTable);
		buildInfoMap();
		model.setModelData(filterAction.isSelected() ? filterInfos() : infos);
	}

	private List<ComponentInfo> filterInfos() {
		List<ComponentInfo> result = new ArrayList<>();
		for (ComponentInfo info : infos) {
			if (shouldInclude(info)) {
				result.add(info);
			}
		}
		return result;
	}

	private void buildInfoMap() {
		for (ComponentInfo info : infos) {
			infoMap.put(info.getComponent(), info);
		}
	}

	private List<ComponentInfo> findComponents(Container root) {
		List<ComponentInfo> infoList = new ArrayList<>();
		if (root == null) {
			return infoList;
		}
		ComponentInfo rootInfo = new ComponentInfo(null, root, 0);
		infoList.add(rootInfo);
		for (int i = 0; i < root.getComponentCount(); i++) {
			Component comp = root.getComponent(i);
			ComponentInfo info = new ComponentInfo(rootInfo, comp, i);
			infoList.add(info);
			addChildInfos(infoList, info);
		}

		return infoList;
	}

	private void addChildInfos(List<ComponentInfo> infoList, ComponentInfo parentInfo) {
		if (parentInfo.getComponent() instanceof Container container) {
			for (int i = 0; i < container.getComponentCount(); i++) {
				Component comp = container.getComponent(i);
				ComponentInfo info = new ComponentInfo(parentInfo, comp, i);
				infoList.add(info);
				addChildInfos(infoList, info);
			}
		}
	}

	private boolean shouldInclude(ComponentInfo info) {
		Component component = info.getComponent();
		if (!component.isFocusable()) {
			return false;
		}
		if (component instanceof JPanel jPanel) {
			if (info.getCycleRootIndex() == null) {
				return false;
			}
		}
		if (component instanceof GGlassPane) {
			return false;
		}
		if (component instanceof JRootPane) {
			return false;
		}
		if (component instanceof JViewport) {
			return false;
		}
		if (component instanceof JLayeredPane) {
			return false;
		}
		if (component instanceof JLabel) {
			return false;
		}
		if (component instanceof JMenu) {
			return false;
		}

		return true;
	}

	private Container findRoot(Component component) {
		if (component.getParent() == null) {
			return component instanceof Container ? (Container) component : null;
		}
		if (component instanceof Window window) {
			return window;
		}
		return findRoot(component.getParent());
	}

	class ComponentTableModel extends GDynamicColumnTableModel<ComponentInfo, Object> {
		private List<ComponentInfo> modelData = new ArrayList<>();

		public ComponentTableModel() {
			super(new ServiceProviderStub());
		}

		void setModelData(List<ComponentInfo> data) {
			this.modelData = new ArrayList<>(data);
			fireTableDataChanged();
		}

		@Override
		public String getName() {
			return ACTION_OWNER;
		}

		@Override
		public List<ComponentInfo> getModelData() {
			return modelData;
		}

		@Override
		protected TableColumnDescriptor<ComponentInfo> createTableColumnDescriptor() {
			TableColumnDescriptor<ComponentInfo> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new ComponentIdColumn(), 1, true);
			descriptor.addVisibleColumn(new ParentIdColumn());
			descriptor.addVisibleColumn(new CycleIndexColumn());
			descriptor.addVisibleColumn(new ComponentNameColumn());
			descriptor.addVisibleColumn(new ComponentClassColumn());
			descriptor.addVisibleColumn(new ToolTipColumn());
			descriptor.addVisibleColumn(new AccessibleNameColumn());
			descriptor.addVisibleColumn(new AccessibleDescriptionColumn());
			descriptor.addHiddenColumn(new FocusableColumn());
			descriptor.addHiddenColumn(new IsFocusCycleRootColumn());
			descriptor.addHiddenColumn(new focusCycleRootColumn());
			descriptor.addVisibleColumn(new TraversalKeysColumn());
			return descriptor;
		}

		@Override
		public Object getDataSource() {
			return null;
		}

		private class ComponentNameColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Name";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				return info.getName();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

		private class ToolTipColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Tool Tip";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				return info.getToolTip();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

		private class AccessibleNameColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Accessible Name";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				AccessibleContext context = info.getComponent().getAccessibleContext();
				if (context != null) {
					return context.getAccessibleName();
				}
				return "";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

		private class AccessibleDescriptionColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Accessible Description";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				AccessibleContext context = info.getComponent().getAccessibleContext();
				if (context != null) {
					return context.getAccessibleDescription();
				}
				return "";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

		private class ComponentClassColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Class";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				return info.getClassSimpleName();

			}

			@Override
			public int getColumnPreferredWidth() {
				return 300;
			}
		}

		private class ComponentIdColumn
				extends AbstractDynamicTableColumn<ComponentInfo, Integer, Object> {

			@Override
			public String getColumnName() {
				return "Id";
			}

			@Override
			public Integer getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				return info.getId();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 50;
			}

		}

		private class ParentIdColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Parent Id";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				ComponentInfo parent = info.getParent();
				return parent == null ? null : parent.getNameAndId();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 50;
			}
		}

		private class TraversalKeysColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Traversal Keys";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				Set<AWTKeyStroke> keys = info.getComponent()
						.getFocusTraversalKeys(
							KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS);
				return keys == null ? "" : keys.toString();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 50;
			}
		}

		private class FocusableColumn
				extends AbstractDynamicTableColumn<ComponentInfo, Boolean, Object> {

			@Override
			public String getColumnName() {
				return "Focusable";
			}

			@Override
			public Boolean getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				return info.isFocusable();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 50;
			}
		}

		private class IsFocusCycleRootColumn
				extends AbstractDynamicTableColumn<ComponentInfo, Boolean, Object> {

			@Override
			public String getColumnName() {
				return "Is Cycle Root";
			}

			@Override
			public Boolean getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				return info.isCycleRoot();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

		private class focusCycleRootColumn
				extends AbstractDynamicTableColumn<ComponentInfo, String, Object> {

			@Override
			public String getColumnName() {
				return "Cycle Root";
			}

			@Override
			public String getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {
				Component component = info.getComponent();
				Container cycleRoot = component.getFocusCycleRootAncestor();
				ComponentInfo cycleRootInfo = getComponentInfo(cycleRoot);
				if (cycleRootInfo != null) {
					return cycleRootInfo.getNameAndId();
				}
				return null;
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

		private class CycleIndexColumn
				extends AbstractDynamicTableColumn<ComponentInfo, Integer, Object> {

			@Override
			public String getColumnName() {
				return "Cycle Index";
			}

			@Override
			public Integer getValue(ComponentInfo info, Settings settings, Object data,
					ServiceProvider provider) throws IllegalArgumentException {

				return info.getCycleRootIndex();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 200;
			}
		}

	}

	class ComponentInfo {
		private static int nextId = 0;
		private ComponentInfo parent;
		private Component component;
		private int id = ++nextId;
		private int depth;
		private String nameAndId;
		private boolean isCycleRoot;
		private List<Component> traversalComps;
		private Integer cycleRootIndex;

		ComponentInfo(ComponentInfo parent, Component component, int indexInParent) {
			this.parent = parent;
			this.component = component;
			this.depth = parent == null ? 0 : parent.depth + 1;
			this.nameAndId = component.getName() + " (" + id + ")";
			this.isCycleRoot = checkIsCycleRoot();
			if (isCycleRoot) {
				this.traversalComps = computeTraversalComps();
			}
		}

		public String getToolTip() {
			if (component instanceof JComponent jComp) {
				return jComp.getToolTipText();
			}
			return null;
		}

		private Integer computeCycleRootIndex() {
			Container cycleRoot = component.getFocusCycleRootAncestor();
			if (cycleRoot == null) {
				return -1;
			}
			ComponentInfo cycleRootInfo = getComponentInfo(cycleRoot);
			List<Component> rootTraversalComps = cycleRootInfo.getTraversalComps();
			return rootTraversalComps.indexOf(component);
		}

		private List<Component> computeTraversalComps() {
			List<Component> traversals = new ArrayList<>();
			Container container = (Container) component;
			FocusTraversalPolicy policy = container.getFocusTraversalPolicy();
			Component comp = policy.getFirstComponent(container);
			while (comp != null && !traversals.contains(comp)) {
				traversals.add(comp);
				comp = policy.getComponentAfter(container, comp);
			}
			return traversals;
		}

		public Integer getCycleRootIndex() {
			if (cycleRootIndex == null) {
				cycleRootIndex = computeCycleRootIndex();
			}
			return cycleRootIndex < 0 ? null : cycleRootIndex;
		}

		public List<Component> getTraversalComps() {
			return traversalComps;
		}

		private boolean checkIsCycleRoot() {
			if (component instanceof Container container) {
				return component.isFocusCycleRoot(container);
			}
			return false;

		}

		public boolean isCycleRoot() {
			return isCycleRoot;
		}

		public String getNameAndId() {
			return nameAndId;
		}

		public String getClassSimpleName() {
			String name = component.getClass()
					.getName();
			int lastIndexOf = name.lastIndexOf(".");
			if (lastIndexOf < 0) {
				return name;
			}
			return name.substring(lastIndexOf + 1);
		}

		public Boolean isFocusable() {
			return component.isFocusable();
		}

		public String getName() {
			return component.getName();
		}

		public int getId() {
			return id;
		}

		public Component getComponent() {
			return component;
		}

		public ComponentInfo getParent() {
			return parent;
		}

		public int getDepth() {
			return depth;
		}

		public static void resetIds() {
			nextId = 0;
		}
	}

	class EventDisplayPanel extends JPanel {
		private static int NUM_MESSAGES = 20;
		private JTextArea text;
		private List<String> messages = new LinkedList<>();

		EventDisplayPanel() {
			super(new BorderLayout());
			setBorder(BorderFactory.createEmptyBorder(0, 10, 2, 10));
			text = new JTextArea(5, 100);
			text.setFont(Gui.getFont(Fonts.MONOSPACED));
			text.setEditable(false);
			JScrollPane scroll = new JScrollPane(text);
			scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
			add(scroll, BorderLayout.CENTER);
		}

		void report(String message) {
			messages.add(message);
			if (messages.size() > NUM_MESSAGES) {
				messages.remove(0);
			}
			text.setText(buildText());
		}

		private String buildText() {
			StringBuilder builder = new StringBuilder();
			for (String message : messages) {
				builder.append(message);
				builder.append("\n");
			}
			return builder.toString();
		}
	}
}
