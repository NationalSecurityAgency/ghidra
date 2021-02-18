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
import java.util.Map.Entry;

import javax.swing.*;

import org.jdom.Element;

import generic.util.WindowUtilities;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.bean.GGlassPane;

/**
 * Node class for managing a component hierarchy in its own sub-window. (currently uses a JDialog)
 */
class DetachedWindowNode extends WindowNode {

	private Window window;
	//private String title;
	private Node child;
	private Rectangle bounds;
	private StatusBar statusBar;
	private JComponent childComp;
	private DropTargetHandler dropTargetHandler;
	private DropTargetFactory dropTargetFactory;

	/**
	 * Constructs a new WindowNode
	 * @param mgr the DockingWindowManager that this node belongs to.
	 * @param parent the parent node (should always be the root node)
	 * @param child the node that manages the component hierarchy.
	 * @param factory the factory from which we create drop targets
	 */
	DetachedWindowNode(DockingWindowManager mgr, Node parent, Node child,
			DropTargetFactory factory) {
		super(mgr);
		this.parent = parent;
		this.child = child;
		this.dropTargetFactory = factory;
		child.parent = this;
		bounds = new Rectangle(0, 0, 0, 0);
	}

	/**
	 * Constructs a new WindowNode from the state information in an XML JDOM element.
	 * @param elem the XML element.
	 * @param mgr the DockingWindowsManager for this node.
	 * @param parent the parent node (should always be the root node)
	 * @param factory the factory from which we create drop targets
	 * @param list child placeholders to be added to this window after being restored
	 */
	DetachedWindowNode(Element elem, DockingWindowManager mgr, Node parent,
			DropTargetFactory factory, List<ComponentPlaceholder> list) {
		super(mgr);
		this.parent = parent;
		this.dropTargetFactory = factory;

		//title = elem.getAttributeValue("TITLE");
		int x = Integer.parseInt(elem.getAttributeValue("X_POS"));
		int y = Integer.parseInt(elem.getAttributeValue("Y_POS"));
		int width = Integer.parseInt(elem.getAttributeValue("WIDTH"));
		int height = Integer.parseInt(elem.getAttributeValue("HEIGHT"));
		bounds = new Rectangle(x, y, width, height);
		Element childElement = (Element) elem.getChildren().get(0);
		child = processChildElement(childElement, mgr, this, list);

	}

	void setInitialLocation(int x, int y) {
		bounds.x = x;
		bounds.y = y;
	}

	void updateTitle() {
		if (window instanceof JDialog) {
			((JDialog) window).setTitle(generateTitle());
		}
		else if (window instanceof JFrame) {
			((JFrame) window).setTitle(generateTitle());
		}
	}

	@Override
	String getTitle() {
		if (window instanceof JDialog) {
			return ((JDialog) window).getTitle();
		}
		else if (window instanceof JFrame) {
			return ((JFrame) window).getTitle();
		}
		return "";
	}

	@Override
	String getDescription() {
		return "Detached Node: " + getTitle();
	}

	@Override
	public String toString() {
		return printTree();
	}

	@Override
	List<Node> getChildren() {
		return Arrays.asList(child);
	}

	/**
	 * Set the Icon this window.
	 * @param iconImage image icon
	 */
	void setIcon(Image iconImage) {
		Frame frame = getFrameForWindow(window);
		if (frame != null) {
			setFrameIcon(frame, iconImage);
		}
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

	private Frame getFrameForWindow(Window coolWindow) {
		if (coolWindow == null) {
			return null;
		}
		if (coolWindow instanceof Frame) {
			return (Frame) coolWindow;
		}

		Container windowParent = coolWindow.getParent();
		if ((windowParent instanceof Window)) {
			return getFrameForWindow((Window) windowParent);
		}

		return null;
	}

	/**
	 * Returns the root pane if window has been created, otherwise null
	 * @return the root pane if window has been created, otherwise null
	 */
	public JRootPane getRootPane() {
		if (window instanceof JDialog) {
			return ((JDialog) window).getRootPane();
		}
		else if (window instanceof JFrame) {
			return ((JFrame) window).getRootPane();
		}
		return null;
	}

	Window getWindow() {
		return window;
	}

	@Override
	Container getContentPane() {
		if (window instanceof JDialog) {
			return ((JDialog) window).getContentPane();
		}
		else if (window instanceof JFrame) {
			return ((JFrame) window).getContentPane();
		}
		return null;
	}

	@Override
	void populateActiveComponents(List<ComponentPlaceholder> list) {
		child.populateActiveComponents(list);
	}

	String generateTitle() {
		return generateTitle(true);
	}

	private String generateTitle(boolean includeToolName) {
		String title = getTitleOfChildren();
		if (title == null) {
			title = "";
		}
		if (includeToolName) {
			title += " [" + ((RootNode) parent).getToolName() + "]";
		}
		return title;
	}

	private String getTitleOfChildren() {
		List<ComponentPlaceholder> placeholders = new ArrayList<>();

		child.populateActiveComponents(placeholders);

		List<String> titles = generateTitles(placeholders);

		boolean firstItem = true;
		StringBuffer buf = new StringBuffer();
		for (String title : titles) {
			if (!firstItem) {
				buf.append(", ");
			}
			firstItem = false;
			buf.append(title);
		}
		return buf.toString();
	}

	/**
	 * Creates a list of titles from the given component providers and placeholders.  The utility
	 * of this method is that it will group like component providers into one title value 
	 * instead of having one value for each placeholder.
	 */
	private List<String> generateTitles(List<ComponentPlaceholder> placeholders) {

		//
		// Decompose the given placeholders into a mapping of provider names to placeholders 
		// that share that name.  This lets us group placeholders that are multiple instances of
		// the same provider.
		//
		Map<String, List<ComponentPlaceholder>> providerNameToPlacholdersMap =
			new HashMap<>();
		for (ComponentPlaceholder placeholder : placeholders) {
			String providerName = placeholder.getProvider().getName();
			List<ComponentPlaceholder> list = providerNameToPlacholdersMap.get(providerName);
			if (list == null) {
				list = new ArrayList<>();
				providerNameToPlacholdersMap.put(providerName, list);
			}
			list.add(placeholder);
		}

		//
		// Turn the created mapping into a mapping of providers names to sub-titles
		//
		Map<String, List<String>> providerNameToTitlesMap = new HashMap<>();
		Set<Entry<String, List<ComponentPlaceholder>>> entrySet =
			providerNameToPlacholdersMap.entrySet();
		for (Entry<String, List<ComponentPlaceholder>> entry : entrySet) {
			String providerName = entry.getKey();
			List<ComponentPlaceholder> placeholdersList = entry.getValue();
			List<String> titles = new ArrayList<>();
			if (placeholdersList.size() == 1) {
				titles.add(placeholdersList.get(0).getTitle());
			}
			else {
				for (ComponentPlaceholder placeholder : placeholdersList) {
					titles.add(placeholder.getTabText());
				}

			}
			providerNameToTitlesMap.put(providerName, titles);
		}

		//
		// Use the created mapping to create an individual title based on a single provider
		// or a group of providers.
		//
		List<String> finalTitles = new ArrayList<>();
		Set<Entry<String, List<String>>> providersEntrySet = providerNameToTitlesMap.entrySet();
		for (Entry<String, List<String>> entry : providersEntrySet) {
			String providerName = entry.getKey();
			List<String> titles = entry.getValue();
			if (titles.size() == 1) {
				finalTitles.add(titles.get(0));
			}
			else {
				StringBuffer buffy = new StringBuffer(providerName);
				buffy.append(" [ ");
				boolean firstItem = true;
				for (String title : titles) {
					if (!firstItem) {
						buffy.append(", ");
					}
					firstItem = false;

					buffy.append(title);
				}
				buffy.append(" ]");
				finalTitles.add(buffy.toString());
			}
		}

		Collections.sort(finalTitles);
		return finalTitles;
	}

	/**
	 * Creates a new window to host the components tree.
	 */
	private void createWindow(JComponent comp) {
		RootNode root = (RootNode) parent;
		if (winMgr.isWindowsOnTop() || root.isModal()) {
			window = createDialog(root);
		}
		else {
			window = createFrame();
		}

		if (dropTargetFactory != null) {
			dropTargetHandler = dropTargetFactory.createDropTargetHandler(window);
		}

		setIcon(winMgr.getRootFrame().getIconImage());
		Container contentPane = getContentPane();

		contentPane.setLayout(new BorderLayout());
		contentPane.add(comp, BorderLayout.CENTER);

		statusBar = new StatusBar();
		contentPane.add(statusBar, BorderLayout.SOUTH);

		window.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				close();
			}

			@Override
			public void windowActivated(WindowEvent e) {
				winMgr.setActive(window, true);
			}

			@Override
			public void windowDeactivated(WindowEvent e) {
				winMgr.setActive(window, false);
			}
		});

		adjustBounds();

		window.setBounds(bounds);
		window.setVisible(true);
	}

	/**
	 * Ensures the bounds of this window have a valid location and size 
	 */
	private void adjustBounds() {

		if (bounds.height == 0 || bounds.width == 0) {
			window.pack();
			Dimension d = window.getSize();
			bounds.height = d.height;
			bounds.width = d.width;
		}

		Window activeWindow = winMgr.getActiveWindow();
		Point p = bounds.getLocation();
		if (p.x == 0 && p.y == 0) {
			p = WindowUtilities.centerOnScreen(activeWindow, bounds.getSize());
			bounds.setLocation(p);
		}

		WindowUtilities.ensureOnScreen(activeWindow, bounds);
	}

	private JFrame createFrame() {
		JFrame newWindow = new DockingFrame(generateTitle());
		newWindow.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		return newWindow;
	}

	private JDialog createDialog(RootNode root) {
		JDialog newWindow = null;
		if (root.isModal()) {
			newWindow = new JDialog(root.getModalDialog(), generateTitle());
		}
		else {
			newWindow = new JDialog(root.getFrame(), generateTitle());
		}

		newWindow.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		GGlassPane glassPane = new GGlassPane();
		newWindow.setGlassPane(glassPane);
		glassPane.setVisible(true);
		return newWindow;
	}

	/**
	 * Sets the visible state of the dialog.
	 * @param state true to show, false to hide.
	 */
	void setVisible(boolean state) {
		if (window != null) {
			window.setVisible(state);
		}
	}

	@Override
	boolean isVisible() {
		return window != null && window.isVisible();
	}

	void updateDialog() {

		if (window != null && childComp != null) {
			bounds = window.getBounds();
			winMgr.getMainWindow().requestFocus();
			getContentPane().remove(childComp);
			window.dispose();
			createWindow(childComp);
		}
	}

	/**
	 * rebuilds the component tree if needed.
	 */
	void update() {
		if (!invalid) {
			return;
		}

		if (childComp != null) {
			getContentPane().remove(childComp);
		}
		childComp = child.getComponent();
		if (childComp != null) {
			if (window == null) {
				createWindow(childComp);
			}
			else {
				getContentPane().add(childComp, BorderLayout.CENTER);
				window.validate();
				window.repaint();
			}
		}
		else if (window != null) {
			bounds = window.getBounds();
			window.setVisible(false);
			window.dispose();
			window = null;
		}
		invalid = false;
		updateTitle();
		clearContextTypes();
		((RootNode) parent).notifyWindowChanged(this);
	}

	@Override
	void dispose() {

		if (dropTargetHandler != null) {
			dropTargetHandler.dispose();
		}

		winMgr.getMainWindow().requestFocus();

		if (window != null) {
			window.setVisible(false);
			window.dispose();
			window = null;
		}

		if (child != null) {
			child.parent = null;
			child.dispose();
			child = null;
		}
	}

	@Override
	void close() {
		child.close();
	}

	@Override
	JComponent getComponent() {
		return null;
	}

	@Override
	void removeNode(Node node) {
		if (node != child) {
			throw new IllegalArgumentException();
		}
		if (window != null) {
			window.setVisible(false);
			window.dispose();
		}
		child.parent = null;
		child = null;
		parent.removeNode(this);
	}

	@Override
	void replaceNode(Node oldNode, Node newNode) {
		if (oldNode == child) {
			child = newNode;
			newNode.parent = this;
			invalidate();
			winMgr.scheduleUpdate();
		}
	}

	@Override
	Element saveToXML() {
		if (window != null) {
			bounds = window.getBounds();
		}

		Element root = new Element("WINDOW_NODE");
		root.setAttribute("X_POS", "" + bounds.x);
		root.setAttribute("Y_POS", "" + bounds.y);
		root.setAttribute("WIDTH", "" + bounds.width);
		root.setAttribute("HEIGHT", "" + bounds.height);
		root.addContent(child.saveToXML());
		return root;

	}

	@Override
	boolean contains(ComponentPlaceholder info) {
		if (child != null) {
			return child.contains(info);
		}
		return false;
	}

	/**
	 * Set the status text
	 * @param text the text
	 */
	public void setStatusText(String text) {
		if (statusBar != null) {
			statusBar.setStatusText(text);
		}
	}

	public void clearStatusMessages() {
		if (statusBar != null) {
			statusBar.clearStatusMessages();
		}
	}

	@Override
	void setMenuBar(JMenuBar menuBar) {
		if (window instanceof JDialog) {
			((JDialog) window).setJMenuBar(menuBar);
		}
		else if (window instanceof JFrame) {
			((JFrame) window).setJMenuBar(menuBar);
		}

	}

	@Override
	void validate() {
		if (window != null) {
			// we've been called before our window has been created
			window.validate();
		}
	}

	@Override
	WindowNode getTopLevelNode() {
		return this;
	}
}
