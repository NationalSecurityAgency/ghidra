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

import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.jdom.Element;

import generic.util.WindowUtilities;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.bean.GGlassPane;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * Root node for the nodes managing the component hierarchy.
 */
class RootNode extends WindowNode {
	static final String ROOT_NODE_ELEMENT_NAME = "ROOT_NODE";
	private WeakSet<DockingWindowListener> dockingWindowListeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	private String toolName;
	private Node child;
	private List<DetachedWindowNode> detachedWindows;
	private JPanel childPanel;
	private StatusBar statusBar;
	private SwingWindowWrapper windowWrapper;

	private DropTargetFactory dropTargetFactory;
	private DropTargetHandler rootDropTargetHandler;

	/**
	 * Constructs a new root node for the given DockingWindowsManager.
	 * @param mgr the DockingWindowsManager
	 * @param toolName the name of the tool to be displayed in all the top-level windows.
	 * @param factory a factory for creating drop targets for this nodes windows; may be null 
	 */
	RootNode(DockingWindowManager mgr, String toolName, List<Image> images, boolean isModal,
			DropTargetFactory factory) {
		super(mgr);
		this.toolName = toolName;
		detachedWindows = new ArrayList<>();

		if (isModal) {
			DockingFrame frame = new HiddenDockingFrame(toolName);
			setFrameIcon(frame, images);
			frame.setBounds(-100, 100, 10, 10);
			JDialog dialog = createDialog(toolName, frame);
			windowWrapper = new JDialogWindowWrapper(new JFrameWindowWrapper(frame), dialog); // change to a dialog type
		}
		else {
			DockingFrame frame = new DockingFrame(toolName);
			setFrameIcon(frame, images);
			windowWrapper = new JFrameWindowWrapper(frame); // default to a frame type			
		}

		Container c = windowWrapper.getContentPane();
		c.setLayout(new BorderLayout());

		childPanel = new JPanel(new BorderLayout());
		childPanel.setBorder(BorderFactory.createEmptyBorder(3, 0, 0, 0));
		c.add(childPanel, BorderLayout.CENTER);

		if (mgr.hasStatusBar()) {
			statusBar = new StatusBar();
			c.add(statusBar, BorderLayout.SOUTH);
		}

		this.dropTargetFactory = factory;
		if (dropTargetFactory != null) {
			rootDropTargetHandler = factory.createDropTargetHandler(getFrame());
		}
	}

	private JDialog createDialog(String title, DockingFrame frame) {
		JDialog dialog = new JDialog(frame, true);
		dialog.setTitle(title);
		dialog.setGlassPane(new GGlassPane());
		return dialog;
	}

	private void setFrameIcon(Frame frame, Image image) {
		List<Image> list = new ArrayList<>();
		list.add(image);
		setFrameIcon(frame, list);
	}

	private void setFrameIcon(Frame frame, List<Image> images) {

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			// the Mac creates better window icons than those we give, since we don't handle the
			// various sizes that the Mac needs.  So, just let the Mac do the preferred thing.
			return;
		}

		if (images != null) {
			frame.setIconImages(images);
		}
	}

	void setHomeButton(Icon icon, Runnable callback) {
		if (!winMgr.hasStatusBar()) {
			return;
		}
		statusBar.setHomeButton(icon, () -> callback.run());
	}

	boolean isModal() {
		return windowWrapper.isModal();
	}

	/**
	 * Return whether the component for this RootNode is visible.
	 */
	@Override
	boolean isVisible() {
		return windowWrapper.isVisible();
	}

	/**
	 * Set the tool name which is displayed as the title
	 * for all windows.
	 * @param toolName tool name / title
	 */
	void setToolName(String toolName) {
		this.toolName = toolName;
		windowWrapper.setTitle(toolName);
		Iterator<DetachedWindowNode> it = detachedWindows.iterator();
		while (it.hasNext()) {
			DetachedWindowNode windowNode = it.next();
			windowNode.updateTitle();
		}

	}

	@Override
	List<Node> getChildren() {
		return Arrays.asList(child);
	}

	@Override
	public String toString() {
		return printTree();
	}

	@Override
	public String getTitle() {
		return windowWrapper.getTitle();
	}

	@Override
	String getDescription() {
		return "Root Node: " + getTitle();
	}

	/**
	 * Set the Icon for all windows.
	 * @param icon image icon
	 */
	void setIcon(ImageIcon icon) {
		Image iconImage = icon.getImage();
		setFrameIcon(windowWrapper.getParentFrame(), iconImage);
		Iterator<DetachedWindowNode> it = detachedWindows.iterator();
		while (it.hasNext()) {
			DetachedWindowNode windowNode = it.next();
			windowNode.setIcon(iconImage);
		}
	}

	/**
	 * Sets the main frame and all sub windows visible state.
	 * @param state true to show them, false to make them invisible.
	 */
	void setVisible(boolean state) {
		Window mainWindow = getMainWindow();
		mainWindow.setVisible(state);
		WindowUtilities.ensureOnScreen(mainWindow);

		Iterator<DetachedWindowNode> it = detachedWindows.iterator();
		while (it.hasNext()) {
			DetachedWindowNode windowNode = it.next();
			windowNode.setVisible(state);
		}
	}

	void add(ComponentPlaceholder info) {
		add(info, (Point) null);
	}

	/**
	 * Creates a new sub-window for the given component a positions it at the given location.
	 * @param info the component to be put in its own window.
	 * @param loc the location for the new window.
	 */
	void add(ComponentPlaceholder info, Point loc) {
		ComponentNode node = new ComponentNode(winMgr);
		info.setNode(node);
		node.parent = this;
		DetachedWindowNode windowNode =
			new DetachedWindowNode(winMgr, this, node, dropTargetFactory);
		if (loc != null) {
			windowNode.setInitialLocation(loc.x, loc.y);
		}
		detachedWindows.add(windowNode);
		info.getNode().add(info);
		info.requestFocus();
		notifyWindowAdded(windowNode);
	}

	/**
	 * Adds the component to the main window.
	 * @param info the component to be added.
	 */
	void add(ComponentPlaceholder info, WindowPosition initialPosition) {
		if (initialPosition == WindowPosition.WINDOW) {
			add(info);
			return;
		}
		ComponentNode node = new ComponentNode(winMgr);
		info.setNode(node);
		if (child == null) {
			node.parent = this;
			child = node;
		}
		else {
			switch (initialPosition) {
				case TOP:
					child = new SplitNode(winMgr, node, child, false);
					break;
				case BOTTOM:
					child = new SplitNode(winMgr, child, node, false);
					break;
				case LEFT:
					child = new SplitNode(winMgr, node, child, true);
					break;
				default: // default to the right
					child = new SplitNode(winMgr, child, node, true);
					break;
			}
			child.parent = this;
		}
		info.getNode().add(info);
	}

	/**
	 * Updates the component hierarchy for the main frame.
	 */
	private void updateChild() {

		JComponent comp = null;
		if (child != null) {
			if (!child.invalid) {
				return;
			}
			comp = child.getComponent();
		}
		if (comp == null) {
			comp = new DockableComponent(null, true);
		}

		childPanel.removeAll();
		childPanel.add(comp, BorderLayout.CENTER);
		childPanel.invalidate();
		clearContextTypes();
		notifyWindowChanged(this);
	}

	/**
	 * Get the window which contains the specified component.
	 * @param info component info
	 * @return window or null if component is not visible or not found.
	 */
	Window getWindow(ComponentPlaceholder info) {
		if (child != null && child.contains(info)) {
			return windowWrapper.getWindow();
		}
		Iterator<DetachedWindowNode> iter = detachedWindows.iterator();
		while (iter.hasNext()) {
			DetachedWindowNode winNode = iter.next();
			if (winNode.contains(info)) {
				return winNode.getWindow();
			}
		}
		return null;
	}

	/**
	 * Updates the component hierarchy for the main frame and all sub-frames.
	 */
	void update() {
		if (invalid) {
			clearContextTypes();
			updateChild();
			Iterator<DetachedWindowNode> it = detachedWindows.iterator();
			while (it.hasNext()) {
				DetachedWindowNode windowNode = it.next();
				windowNode.update();
			}
			invalid = false;
		}

		winMgr.getActionToGuiMapper().update();
		windowWrapper.validate();
	}

	void updateDialogs() {
		Iterator<DetachedWindowNode> it = detachedWindows.iterator();
		while (it.hasNext()) {
			DetachedWindowNode windowNode = it.next();
			windowNode.updateDialog();
		}
	}

	@Override
	void setMenuBar(JMenuBar menuBar) {
		windowWrapper.setJMenuBar(menuBar);
	}

	@Override
	void validate() {
		windowWrapper.validate();
	}

	@Override
	void close() {
		throw new UnsupportedOperationException("Cannot call close on root node");
	}

	@Override
	JComponent getComponent() {
		return null;
	}

	@Override
	void removeNode(Node node) {
		if (child != node && !detachedWindows.contains(node)) {
			throw new IllegalArgumentException();
		}
		if (child == node) {
			child = null;
		}
		else {
			detachedWindows.remove(node);
			notifyWindowRemoved((DetachedWindowNode) node);
		}
		node.parent = null;
	}

	/**
	 * Returns the main frame of the tool.
	 */
	public JFrame getFrame() {
		return windowWrapper.getParentFrame();
	}

	JDialog getModalDialog() {
		if (windowWrapper.isModal()) {
			return (JDialog) windowWrapper.getWindow();
		}
		return null;
	}

	@Override
	void populateActiveComponents(List<ComponentPlaceholder> list) {
		if (child != null) {
			child.populateActiveComponents(list);
		}
	}

	String getName() {
		return toolName;
	}

	/**
	 * Returns list of detached windows (WindowNode objects).
	 */
	public List<DetachedWindowNode> getDetachedWindows() {
		return detachedWindows;
	}

	/**
	 * Returns the tool name of the tool.
	 * @return the tool name of the tool.
	 */
	String getToolName() {
		return toolName;
	}

	@Override
	void replaceNode(Node oldNode, Node newNode) {
		if (oldNode == child) {
			child = newNode;
			newNode.parent = this;
			child.invalidate();
			winMgr.scheduleUpdate();
		}
	}

	@Override
	Container getContentPane() {
		return windowWrapper.getContentPane();
	}

	@Override
	Element saveToXML() {
		Element root = new Element(ROOT_NODE_ELEMENT_NAME);
		JFrame frame = windowWrapper.getParentFrame();
		Rectangle r = frame.getBounds();
		root.setAttribute("X_POS", "" + r.x);
		root.setAttribute("Y_POS", "" + r.y);
		root.setAttribute("WIDTH", "" + r.width);
		root.setAttribute("HEIGHT", "" + r.height);
		root.setAttribute("EX_STATE", "" + frame.getExtendedState());
		if (child != null) {
			root.addContent(child.saveToXML());
		}
		Iterator<DetachedWindowNode> it = detachedWindows.iterator();
		while (it.hasNext()) {
			DetachedWindowNode windowNode = it.next();
			root.addContent(windowNode.saveToXML());
		}
		return root;
	}

	/**
	 * Restores the component hierarchy from the given XML JDOM element.
	 * @param root the XML from which to restore the state.
	 */
	List<ComponentPlaceholder> restoreFromXML(Element rootNodeElement) {
		invalid = true;
		detachChild();
		setLastFocusedProviderInWindow(null);   // clear out stale last focused provider
		List<DetachedWindowNode> copy = new ArrayList<>(detachedWindows);
		detachedWindows.clear();
		for (DetachedWindowNode windowNode : copy) {
			notifyWindowRemoved(windowNode);
			windowNode.dispose();
		}

		int x = Integer.parseInt(rootNodeElement.getAttributeValue("X_POS"));
		int y = Integer.parseInt(rootNodeElement.getAttributeValue("Y_POS"));
		int width = Integer.parseInt(rootNodeElement.getAttributeValue("WIDTH"));
		int height = Integer.parseInt(rootNodeElement.getAttributeValue("HEIGHT"));
		JFrame frame = windowWrapper.getParentFrame();
		Rectangle bounds = new Rectangle(x, y, width, height);
		WindowUtilities.ensureOnScreen(frame, bounds);
		frame.setBounds(bounds);

		List<ComponentPlaceholder> restoredPlaceholders = new ArrayList<>();
		Iterator<?> elementIterator = rootNodeElement.getChildren().iterator();
		while (elementIterator.hasNext()) {
			Element elem = (Element) elementIterator.next();

			if (elem.getName().equals("WINDOW_NODE")) {
				Node node = new DetachedWindowNode(elem, winMgr, this, dropTargetFactory,
					restoredPlaceholders);
				DetachedWindowNode windowNode = (DetachedWindowNode) node;
				detachedWindows.add(windowNode);
				notifyWindowAdded(windowNode);
			}
			else {
				child = processChildElement(elem, winMgr, this, restoredPlaceholders);
			}
		}

		return restoredPlaceholders;
	}

	private void detachChild() {
		if (child == null) {
			return;
		}

		child.parent = null;
		child = null;
	}

	/**
	 * Release all resources. The root node is no longer viable.
	 */
	@Override
	void dispose() {

		dockingWindowListeners.clear();
		if (child != null) {
			child.dispose();
		}

		super.dispose();

		if (rootDropTargetHandler != null) {
			rootDropTargetHandler.dispose();
		}

		Iterator<DetachedWindowNode> it = detachedWindows.iterator();
		while (it.hasNext()) {
			DetachedWindowNode windowNode = it.next();
			notifyWindowRemoved(windowNode);
			windowNode.dispose();
		}
		detachedWindows.clear();

		windowWrapper.dispose();
	}

	@Override
	boolean contains(ComponentPlaceholder info) {
		if (child != null && child.contains(info)) {
			return true;
		}
		Iterator<DetachedWindowNode> iter = detachedWindows.iterator();
		while (iter.hasNext()) {
			DetachedWindowNode winNode = iter.next();
			if (winNode.contains(info)) {
				return true;
			}
		}
		return false;
	}

	public void addStatusItem(JComponent c, boolean addBorder, boolean rightSide) {
		if (statusBar != null) {
			statusBar.addStatusItem(c, addBorder, rightSide);
			windowWrapper.validate();
		}
	}

	public void removeStatusItem(JComponent c) {
		if (statusBar != null) {
			statusBar.removeStatusItem(c);
			windowWrapper.validate();
		}
	}

	public void clearStatusMessages() {
		if (statusBar == null) {
			return;
		}

		if (statusBar == null) {
			return;
		}

		statusBar.clearStatusMessages();

		Iterator<DetachedWindowNode> iter = detachedWindows.iterator();
		while (iter.hasNext()) {
			DetachedWindowNode winNode = iter.next();
			winNode.clearStatusMessages();
		}
	}

	public void setStatusText(String text) {
		if (statusBar == null) {
			return;
		}

		statusBar.setStatusText(text);

		Iterator<DetachedWindowNode> iter = detachedWindows.iterator();
		while (iter.hasNext()) {
			DetachedWindowNode winNode = iter.next();
			winNode.setStatusText(text);
		}
	}

	public Window getMainWindow() {
		return windowWrapper.getWindow();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	/** Interface to wrap JDialog and JFrame so that they can be used by one handle */
	private interface SwingWindowWrapper {
		boolean isVisible();

		boolean isModal();

		void validate();

		Container getContentPane();

		void setJMenuBar(JMenuBar menuBar);

		void dispose();

		Window getWindow();

		JFrame getParentFrame();

		void setTitle(String title);

		String getTitle();
	}

	private class JDialogWindowWrapper implements SwingWindowWrapper {

		private final JDialog wrappedDialog;
		private final SwingWindowWrapper parentFrame;
		private WindowAdapter windowListener;

		public JDialogWindowWrapper(SwingWindowWrapper parentFrame, JDialog dialog) {
			this.parentFrame = parentFrame;
			this.wrappedDialog = dialog;

			dialog.setSize(800, 400);
			dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

			windowListener = new WindowAdapter() {

				@Override
				public void windowClosed(WindowEvent e) {
					// do not call close() here, as it is an operation that can be cancelled
					winMgr.setVisible(false);
				}

				@Override
				public void windowClosing(WindowEvent e) {
					winMgr.close();
				}

				@Override
				public void windowActivated(WindowEvent e) {
					winMgr.setActive(wrappedDialog, true);
				}
			};

			dialog.addWindowListener(windowListener);
		}

		@Override
		public void dispose() {
			wrappedDialog.setVisible(false);
			wrappedDialog.removeWindowListener(windowListener);
			wrappedDialog.dispose();
			parentFrame.dispose();
		}

		@Override
		public Container getContentPane() {
			return wrappedDialog.getContentPane();
		}

		@Override
		public Window getWindow() {
			return wrappedDialog;
		}

		@Override
		public boolean isVisible() {
			return wrappedDialog.isVisible();
		}

		@Override
		public void setJMenuBar(JMenuBar menuBar) {
			wrappedDialog.setJMenuBar(menuBar);
		}

		@Override
		public void validate() {
			wrappedDialog.validate();
		}

		@Override
		public JFrame getParentFrame() {
			return parentFrame.getParentFrame();
		}

		@Override
		public void setTitle(String title) {
			wrappedDialog.setTitle(title);
		}

		@Override
		public String getTitle() {
			return wrappedDialog.getTitle();
		}

		@Override
		public boolean isModal() {
			return true;
		}
	}

	private class JFrameWindowWrapper implements SwingWindowWrapper {

		private final JFrame wrappedFrame;
		private WindowAdapter windowListener;

		public JFrameWindowWrapper(final JFrame wrappedFrame) {
			this.wrappedFrame = wrappedFrame;
			wrappedFrame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

			windowListener = new WindowAdapter() {

				@Override
				public void windowClosed(WindowEvent e) {
					// do not call close() here, as it is an operation that can be cancelled
					winMgr.setVisible(false);
				}

				@Override
				public void windowClosing(WindowEvent e) {
					winMgr.close();
				}

				@Override
				public void windowActivated(WindowEvent e) {
					winMgr.setActive(wrappedFrame, true);
				}

				@Override
				public void windowDeactivated(WindowEvent e) {
					winMgr.setActive(wrappedFrame, false);
				}

				@Override
				public void windowIconified(WindowEvent e) {
					winMgr.iconify();
				}

				@Override
				public void windowDeiconified(WindowEvent e) {
					winMgr.deIconify();
				}
			};
			wrappedFrame.addWindowListener(windowListener);

			wrappedFrame.setSize(800, 400);
		}

		@Override
		public void dispose() {
			wrappedFrame.removeWindowListener(windowListener);
			wrappedFrame.setVisible(false);
			wrappedFrame.dispose();
		}

		@Override
		public Container getContentPane() {
			return wrappedFrame.getContentPane();
		}

		@Override
		public Window getWindow() {
			return wrappedFrame;
		}

		@Override
		public boolean isVisible() {
			return wrappedFrame.isVisible();
		}

		@Override
		public void setJMenuBar(JMenuBar menuBar) {
			wrappedFrame.setJMenuBar(menuBar);
		}

		@Override
		public void validate() {
			wrappedFrame.validate();
		}

		@Override
		public JFrame getParentFrame() {
			return wrappedFrame;
		}

		@Override
		public void setTitle(String title) {
			wrappedFrame.setTitle(title);
		}

		@Override
		public String getTitle() {
			return wrappedFrame.getTitle();
		}

		@Override
		public boolean isModal() {
			return false;
		}

	}

	public void addDockingWindowListener(DockingWindowListener listener) {
		dockingWindowListeners.add(listener);
	}

	public void removeDockingWindowListener(DockingWindowListener listener) {
		dockingWindowListeners.remove(listener);
	}

	void notifyWindowAdded(DetachedWindowNode windowNode) {
		for (DockingWindowListener listener : dockingWindowListeners) {
			listener.dockingWindowAdded(windowNode);
		}
	}

	private void notifyWindowRemoved(DetachedWindowNode windowNode) {
		for (DockingWindowListener listener : dockingWindowListeners) {
			listener.dockingWindowRemoved(windowNode);
		}
	}

	void notifyWindowChanged(WindowNode windowNode) {
		for (DockingWindowListener listener : dockingWindowListeners) {
			listener.dockingWindowChanged(windowNode);
		}
	}

	void notifyWindowFocusChanged(WindowNode windowNode) {
		for (DockingWindowListener listener : dockingWindowListeners) {
			listener.dockingWindowFocusChanged(windowNode);
		}
	}

	@Override
	WindowNode getTopLevelNode() {
		return this;
	}

	public WindowNode getNodeForWindow(Window win) {
		if (windowWrapper.getWindow() == win) {
			return this;
		}
		for (DetachedWindowNode windowNode : detachedWindows) {
			if (windowNode.getWindow() == win) {
				return windowNode;
			}
		}
		return null;
	}

}
