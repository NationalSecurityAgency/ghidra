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
package docking;

import java.awt.Component;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import org.jdom.Element;

import docking.help.HelpService;
import docking.widgets.OptionDialog;
import docking.widgets.tabbedpane.DockingTabRenderer;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Node object for managing one or more components. If more that one managed component
 * is active, then this node will create a tabbedPane object to contain the active components.
 */
class ComponentNode extends Node {

	private ComponentPlaceholder top;
	private List<ComponentPlaceholder> windowPlaceholders;
	private JComponent comp;
	private boolean isDisposed;

	// keep track of top ComponentWindowingPlaceholder
	private ChangeListener tabbedPaneChangeListener = e -> {
		Component selectedComponent = ((JTabbedPane) comp).getSelectedComponent();
		for (ComponentPlaceholder placeholder : windowPlaceholders) {
			if (placeholder.getComponent() == selectedComponent) {
				top = placeholder;
				break;
			}
		}
		Swing.runLater(() -> {
			if (top != null) {
				top.requestFocus();
			}
		});
	};

	/**
	 * Constructs a new component node with the given docking windows manager.
	 * @param mgr the docking windows manager that this node belongs to.
	 */
	ComponentNode(DockingWindowManager mgr) {
		super(mgr);
		windowPlaceholders = new ArrayList<>();
	}

	/**
	 * Constructs a new component node from the given xml element.
	 * @param elem the xml element describing the configuration of this node.
	 * @param mgr the docking windows manager
	 * @param parent the parent node for this node.
	 * @param restoredPlaceholders the list into which any restored placeholders will be placed
	 */
	ComponentNode(Element elem, DockingWindowManager mgr, Node parent,
			List<ComponentPlaceholder> restoredPlaceholders) {
		super(mgr);

		this.parent = parent;
		windowPlaceholders = new ArrayList<>();

		int topIndex = Integer.parseInt(elem.getAttributeValue("TOP_INFO"));

		Iterator<?> it = elem.getChildren().iterator();
		while (it.hasNext()) {
			Element e = (Element) it.next();
			String name = e.getAttributeValue("NAME");
			String owner = e.getAttributeValue("OWNER");
			String title = e.getAttributeValue("TITLE");
			String group = e.getAttributeValue("GROUP");
			if (group == null || group.trim().isEmpty()) {
				group = ComponentProvider.DEFAULT_WINDOW_GROUP;
			}

			boolean isActive = Boolean.valueOf(e.getAttributeValue("ACTIVE")).booleanValue();

			long uniqueID = getUniqueID(e, 0);

			String mappedOwner = ComponentProvider.getMappedOwner(owner, name);
			if (mappedOwner != null) {
				name = ComponentProvider.getMappedName(owner, name);
				owner = mappedOwner;
			}

			ComponentPlaceholder placeholder =
				new ComponentPlaceholder(name, owner, group, title, isActive, this, uniqueID);

			if (!containsPlaceholder(placeholder)) {
				windowPlaceholders.add(placeholder);
				restoredPlaceholders.add(placeholder);
			}
		}
		if (topIndex >= 0 && topIndex < windowPlaceholders.size()) {
			top = windowPlaceholders.get(topIndex);
		}
	}

	private boolean containsPlaceholder(ComponentPlaceholder placeholder) {
		// Note: we purposely didn't override equals here, as other code here relies on the default
		// equals() implementation to locate placeholders

		String group = placeholder.getGroup();
		if (group == null) {
			group = "";
		}

		String owner = placeholder.getOwner();
		String name = placeholder.getName();
		String title = placeholder.getTitle();
		for (ComponentPlaceholder existingPlaceholder : windowPlaceholders) {
			if (existingPlaceholder.getOwner().equals(owner) &&
				existingPlaceholder.getName().equals(name) &&
				existingPlaceholder.getGroup().equals(group) &&
				existingPlaceholder.getTitle().equals(title)) {
				return true;
			}
		}
		return false;
	}

	private long getUniqueID(Element e, long defaultValue) {
		String attributeValue = e.getAttributeValue("INSTANCE_ID");
		if (attributeValue == null) {
			return defaultValue;
		}
		return Long.parseLong(attributeValue);
	}

	@Override
	List<Node> getChildren() {
		return Collections.emptyList(); // this class is a leaf
	}

	@Override
	public String toString() {
		return printTree();
	}

	@Override
	String getDescription() {
		return windowPlaceholders.toString();
	}

	/**
	 * Adds a component to this node.
	 * @param placeholder the component placeholder containing the component to be added.
	 */
	void add(ComponentPlaceholder placeholder) {
		windowPlaceholders.add(placeholder);
		placeholder.setNode(this);
		if (placeholder.isShowing()) {
			top = placeholder;
			invalidate();
		}
		WindowNode topLevelNode = getTopLevelNode();
		topLevelNode.componentAdded(placeholder);
	}

	/**
	 * Removes the component from this node, but not from the manager. Used when
	 * the component is moved.  If component is active, it will remain active.
	 * @param placeholder the object containing the component to be removed.
	 */
	void remove(ComponentPlaceholder placeholder) {
		if (getTopLevelNode() == null) {
			return;   // this node has been disconnected.
		}

		if (placeholder.isShowing()) {
			if (top == placeholder) {
				top = null;
			}
			invalidate();
		}

		WindowNode topLevelNode = getTopLevelNode();
		topLevelNode.componentRemoved(placeholder);
		doRemove(placeholder);
	}

	private void doRemove(ComponentPlaceholder placeholder) {
		windowPlaceholders.remove(placeholder);
		placeholder.setNode(null);
		if (windowPlaceholders.isEmpty()) {
			parent.removeNode(this);
		}
	}

	/**
	 * Removes the component from this node (and the manager), but possibly keeps an empty object as
	 * a placeholder.
	 * @param placeholder the placeholder object to be removed.
	 * @param keepEmptyPlaceholder flag indicating to keep a placeholder placeholder object.
	 */
	void remove(ComponentPlaceholder placeholder, boolean keepEmptyPlaceholder) {
		if (placeholder.isShowing()) {
			placeholder.show(false);
			if (top == placeholder) {
				top = null;
			}
			invalidate();
			winMgr.scheduleUpdate();
		}

		placeholder.setProvider(null);
		if (!keepEmptyPlaceholder) {
			doRemove(placeholder);
		}
	}

	int getComponentCount() {
		return windowPlaceholders.size();
	}

	@Override
	void close() {
		List<ComponentPlaceholder> list = new ArrayList<>(windowPlaceholders);
		Iterator<ComponentPlaceholder> it = list.iterator();
		while (it.hasNext()) {
			ComponentPlaceholder placeholder = it.next();
			if (placeholder.isShowing()) {
				placeholder.close();
			}
		}
	}

	@Override
	JComponent getComponent() {

		if (isDisposed) {
			throw new AssertException(
				"Attempted to reuse a disposed component window node");
		}

		if (!invalid) {
			return comp;
		}

		if (comp instanceof JTabbedPane) {
			((JTabbedPane) comp).removeChangeListener(tabbedPaneChangeListener);
			comp.removeAll();
		}
		comp = null;

		List<ComponentPlaceholder> activeComponents = new ArrayList<>();
		populateActiveComponents(activeComponents);
		int count = activeComponents.size();
		if (count == 1) {

			//
			// TODO Hack Alert!  (When this is removed, also update ComponentPlaceholder)
			// 
			ComponentPlaceholder nextTop = activeComponents.get(0);
			if (nextTop.isDisposed()) {
				// This should not happen!  We have seen this bug recently
				Msg.debug(this, "Found disposed component that was not removed from the active " +
					"list: " + nextTop, ReflectionUtilities.createJavaFilteredThrowable());
				return null;
			}

			top = activeComponents.get(0);
			comp = top.getComponent();
			comp.setBorder(BorderFactory.createRaisedBevelBorder());

			installRenameMenu(top, null);
		}
		else if (count > 1) {
			JTabbedPane pane =
				new JTabbedPane(SwingConstants.BOTTOM, JTabbedPane.SCROLL_TAB_LAYOUT);
			comp = pane;
			int topIndex = 0;
			for (int i = 0; i < count; i++) {
				ComponentPlaceholder placeholder = activeComponents.get(i);
				DockableComponent c = placeholder.getComponent();
				c.setBorder(BorderFactory.createEmptyBorder());
				String title = placeholder.getTitle();
				String tabText = placeholder.getTabText();

				final DockableComponent component = placeholder.getComponent();
				pane.add(component, title);

				DockingTabRenderer tabRenderer =
					createTabRenderer(pane, placeholder, title, tabText, component);

				c.installDragDropTarget(pane);

				pane.setTabComponentAt(i, tabRenderer);
				Icon icon = placeholder.getIcon();
				if (icon != null) {
					tabRenderer.setIcon(icon);
				}

				if (placeholder == top) {
					topIndex = i;
				}
			}
			DockableComponent activeComp = (DockableComponent) pane.getComponentAt(topIndex);
			top = activeComp.getComponentWindowingPlaceholder();
			pane.setSelectedComponent(activeComp);
			pane.addChangeListener(tabbedPaneChangeListener);
		}
		invalid = false;
		return comp;
	}

	private DockingTabRenderer createTabRenderer(JTabbedPane pane, ComponentPlaceholder placeholder,
			String title, String tabText, final DockableComponent component) {
		DockingTabRenderer tabRenderer =
			new DockingTabRenderer(pane, title, tabText, e -> closeTab(component));

		installRenameMenu(placeholder, tabRenderer);

		return tabRenderer;
	}

	private void installRenameMenu(ComponentPlaceholder placeholder,
			DockingTabRenderer tabRenderer) {

		final ComponentProvider provider = placeholder.getProvider();
		if (!provider.isTransient() || provider.isSnapshot()) {
			return; // don't muck with the title of 'real' providers--only transients, like search
		}

		MouseAdapter listener = new RenameMouseListener(placeholder);

		// for use on the header
		DockableComponent dockableComponent = placeholder.getComponent();
		DockableHeader header = dockableComponent.getHeader();
		header.installRenameAction(listener);

		// for use on the tab
		if (tabRenderer != null) {
			tabRenderer.installRenameAction(listener);
		}
	}

	@Override
	void populateActiveComponents(List<ComponentPlaceholder> list) {
		for (ComponentPlaceholder placeholder : windowPlaceholders) {
			if (placeholder.isShowing()) {
				list.add(placeholder);
			}
		}
	}

	@Override
	void removeNode(Node node) {
		throw new UnsupportedOperationException();
	}

	@Override
	void replaceNode(Node oldNode, Node newNode) {
		// I have no child nodes so ignore
	}

	/**
	 * Replaces this node in its parent with a new split node that contains this node as one
	 * child and a new componentNode containing the source placeholders as the other child. 
	 * 
	 * @param source the placeholder to share the current space with. 
	 * @param dropCode int value specifying the split order and orientation.
	 */
	void split(ComponentPlaceholder source, WindowPosition dropCode) {
		ComponentNode sourceNode = new ComponentNode(winMgr);
		source.setNode(sourceNode);
		SplitNode splitNode;
		Node parentNode = parent;
		switch (dropCode) {
			case LEFT:
				splitNode = new SplitNode(winMgr, sourceNode, this, true);
				break;
			case RIGHT:
				splitNode = new SplitNode(winMgr, this, sourceNode, true);
				break;
			case TOP:
				splitNode = new SplitNode(winMgr, sourceNode, this, false);
				break;
			case BOTTOM:
				splitNode = new SplitNode(winMgr, this, sourceNode, false);
				break;
			default:
				// default to the right
				splitNode = new SplitNode(winMgr, this, sourceNode, true);

		}

		parentNode.replaceNode(this, splitNode);
		sourceNode.add(source);
	}

	/**
	 * Returns true if there are currently more than one active component in this node.
	 * @return true if there are currently more than one active component in this node.
	 */
	boolean isStacked() {
		return comp instanceof JTabbedPane;
	}

	/**
	 * Makes the component the selected tab.
	 * @param placeholder the component placeholder object of the component to be shown in the active tab.
	 */
	public void makeSelectedTab(ComponentPlaceholder placeholder) {
		if (invalid) {
			return;
		}

		if (!(comp instanceof JTabbedPane)) {
			return;
		}

		DockableComponent dc = placeholder.getComponent();
		if (dc != null) {
			JTabbedPane tab = (JTabbedPane) comp;
			if (tab.getSelectedComponent() != dc) {
				tab.setSelectedComponent(dc);
			}
		}
	}

	@Override
	Element saveToXML() {
		Element root = new Element("COMPONENT_NODE");
		int topIndex = 0;
		if (top != null) {
			for (int i = 0; i < windowPlaceholders.size(); i++) {
				ComponentPlaceholder placeholder = windowPlaceholders.get(i);
				if (placeholder == top) {
					topIndex = i;
					break;
				}
			}
		}
		root.setAttribute("TOP_INFO", "" + topIndex);
		Iterator<ComponentPlaceholder> it = windowPlaceholders.iterator();
		while (it.hasNext()) {

			ComponentPlaceholder placeholder = it.next();

			Element elem = new Element("COMPONENT_INFO");
			elem.setAttribute("NAME", placeholder.getName());
			elem.setAttribute("OWNER", placeholder.getOwner());
			elem.setAttribute("TITLE", placeholder.getTitle());
			elem.setAttribute("ACTIVE", "" + placeholder.isShowing());
			elem.setAttribute("GROUP", placeholder.getGroup());
			elem.setAttribute("INSTANCE_ID", Long.toString(placeholder.getInstanceID()));
			root.addContent(elem);
		}
		return root;
	}

	//
	// Tabbed pane listener methods
	//
	@Override
	boolean contains(ComponentPlaceholder placeholder) {
		for (ComponentPlaceholder ph : windowPlaceholders) {
			if (ph.isShowing() && ph.equals(placeholder)) {
				return true;
			}
		}
		return false;
	}

	void titleChanged(ComponentPlaceholder placeholder) {
		if (!(comp instanceof JTabbedPane)) {
			return;
		}

		JTabbedPane pane = (JTabbedPane) comp;
		int index = pane.indexOfComponent(placeholder.getComponent());
		if (index == -1) {
			return;
		}

		DockingTabRenderer renderer = (DockingTabRenderer) pane.getTabComponentAt(index);
		renderer.setIcon(placeholder.getIcon());

		String tabText = placeholder.getTabText();
		String fullTitle = placeholder.getTitle();
		renderer.setTitle(tabText, fullTitle);
	}

	public void iconChanged(ComponentPlaceholder placeholder) {
		if (!(comp instanceof JTabbedPane)) {
			return;
		}

		JTabbedPane pane = (JTabbedPane) comp;
		int index = pane.indexOfComponent(placeholder.getComponent());
		if (index == -1) {
			return;
		}

		DockingTabRenderer renderer = (DockingTabRenderer) pane.getTabComponentAt(index);
		renderer.setIcon(placeholder.getIcon());
		pane.setIconAt(index, placeholder.getIcon());
	}

	private void closeTab(Component tabComponent) {
		if (!(comp instanceof JTabbedPane)) {
			return; // shouldn't happen since this is usually a callback from a widget on a tab
		}

		ComponentPlaceholder placeholder = getPlaceHolderForComponent(tabComponent);
		if (placeholder != null) {
			// this shouldn't be null, but there seems to be some timing issue where this can 
			// be null when rapidly closing tabs
			placeholder.close();
		}
	}

	private ComponentPlaceholder getPlaceHolderForComponent(Component component) {
		for (ComponentPlaceholder placeholder : windowPlaceholders) {
			if (component == placeholder.getComponent()) {
				return placeholder;
			}
		}
		return null;
	}

	@Override
	WindowNode getTopLevelNode() {
		if (parent != null) {
			return parent.getTopLevelNode();
		}
		return null;
	}

	@Override
	void dispose() {
		isDisposed = true;
		if (top != null) {
			top.dispose();
		}
		windowPlaceholders.clear();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class RenameMouseListener extends MouseAdapter {

		private static final HelpLocation RENAME_HELP =
			new HelpLocation("DockingWindows", "Renaming_Windows");
		private ComponentPlaceholder placeholder;

		RenameMouseListener(ComponentPlaceholder placeholder) {
			this.placeholder = placeholder;
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			// Note: we don't really care about the type of mouse event; we just want the location.
			//      (the event may not actually be a clicked event, depending on the platform)

			JMenuItem menuItem = new JMenuItem("Rename");
			menuItem.addActionListener(new RenameActionListener());
			HelpService helpService = DockingWindowManager.getHelpService();
			helpService.registerHelp(menuItem, RENAME_HELP);

			JPopupMenu menu = new JPopupMenu();
			menu.add(menuItem);
			menu.show(e.getComponent(), e.getX(), e.getY());
		}

		private class RenameActionListener implements ActionListener {
			@Override
			public void actionPerformed(ActionEvent event) {
				ComponentProvider provider = placeholder.getProvider();
				JComponent component = provider.getComponent();
				String currentTabText = provider.getTabText();
				String newName = OptionDialog.showInputSingleLineDialog(component, "Rename Tab",
					"New name:", currentTabText);
				if (newName == null || newName.isEmpty()) {
					return; // cancelled
				}

				// If the user changes the name, then we want to replace all of the
				// parts of the title with that name.  We skip the subtitle, as that 
				// doesn't make sense in that case.
				provider.setTitle(newName);   // title on window
				provider.setSubTitle("");     // part after the title
				provider.setTabText(newName); // text on the tab
				placeholder.update();
			}
		}
	}
}
