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
package ghidra.app.plugin.core.progmgr;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.border.*;

import docking.actions.KeyBindingUtils;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GIconLabel;
import generic.util.WindowUtilities;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.HorizontalLayout;
import resources.ResourceManager;

/**
 * Panel to show a "tab" for an object. ChangeListeners are notified when a tab is selected. 
 */
public class MultiTabPanel extends JPanel {

	private final static Color SELECTED_TAB_COLOR = new Color(120, 140, 189);
	private final static Color HIGHLIGHTED_TAB_COLOR = SELECTED_TAB_COLOR.brighter();
	private final static Icon EMPTY16_ICON = ResourceManager.loadImage("images/EmptyIcon16.gif");
	private final static Icon EMPTY8_ICON = ResourceManager.loadImage("images/empty8x16.png");
	private final static Icon CLOSE_ICON = ResourceManager.loadImage("images/x.gif");
	private final static Icon HIGHLIGHT_CLOSE_ICON = ResourceManager.loadImage("images/pinkX.gif");
	private final static Icon LIST_ICON = ResourceManager.loadImage("images/VCRFastForward.gif");
	private final static Icon TRANSIENT_ICON = ResourceManager.loadImage("images/link.png", 8, 16);

	private final static Color TEXT_SELECTION_COLOR = Color.WHITE;
	private final static Color TEXT_NON_SELECTION_COLOR = UIManager.getColor("Tree.textForeground");
	private final static Color BG_SELECTION_COLOR = SELECTED_TAB_COLOR;
	private final static Color BG_NON_SELECTION_COLOR = UIManager.getColor("Panel.background");

	private static final Font LABEL_FONT = new Font("Tahoma", Font.PLAIN, 11);
	private static final Font LIST_LABEL_FONT = new Font("Tahoma", Font.BOLD, 9);
	private static final String DEFAULT_HIDDEN_COUNT_STR = "99";

	/** A list of tabs that are hidden from view due to space constraints */
	private List<TabPanel> hiddenTabList;

	/** A visible tab list */
	private List<TabPanel> visibleTabList;

	/** A linked map to maintain insertion order mapping of programs and their associated tabs */
	private Map<Program, TabPanel> linkedProgramMap;

	private Program currentProgram;
	private Program highlightedProgram;
	private MultiTabPlugin multiTabPlugin;
	private ProgramListPanel programListPanel;
	private Border defaultListLabelBorder;
	private Border noTabsBorder;
	private Border tabbedBorder;
	private JLabel showHiddenListLabel;
	private JDialog listWindow;
	private JTextField filterField;

	// for testing
	private boolean ignoreFocus;

	MultiTabPanel(MultiTabPlugin multiTabPlugin) {
		super();
		this.multiTabPlugin = multiTabPlugin;
		setLayout(new HorizontalLayout(0));

		// we use a linked map to maintain insertion order
		linkedProgramMap = new LinkedHashMap<>();
		hiddenTabList = new ArrayList<>();
		visibleTabList = new ArrayList<>();

		// Create a border that is designed to draw a rectangle along the bottom of the
		// panel that will accent the selected tab. This line is intended to appear as
		// it is part of the selected tab.
		Border outerBorder = new MatteBorder(0, 0, 3, 0, SELECTED_TAB_COLOR);
		Border innerBorder = new BottomOnlyBevelBorder();
		setBorder(BorderFactory.createCompoundBorder(outerBorder, innerBorder));

		showHiddenListLabel = createLabel();

		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				hideListWindow();
				packTabs(currentProgram);
			}
		});
		setMinimumSize(new Dimension(30, 20));
	}

	void addProgram(Program program) {
		if (linkedProgramMap.containsKey(program)) {
			return;
		}

		JPanel panel = createProgramTab(program, false);
		add(panel);
		packTabs(currentProgram);
	}

	/**
	 * Remove all tabs in the panel.
	 */
	@Override
	public void removeAll() {
		currentProgram = null;
		ArrayList<Program> list = new ArrayList<>(linkedProgramMap.keySet());

		for (int i = 0; i < list.size(); i++) {
			doRemoveProgram(list.get(i));
		}
		linkedProgramMap.clear();
		visibleTabList.clear();
		hiddenTabList.clear();
		hideListWindow();
	}

	Program getSelectedProgram() {
		return currentProgram;
	}

	/**
	 * Refresh label displayed in the tab for the given object. 
	 * @param program object associated with a tab
	 */
	void refresh(Program program) {
		TabPanel panel = linkedProgramMap.get(program);
		if (panel == null) {
			return;
		}

		panel.refresh();
		packTabs(currentProgram);
	}

	/**
	 * Set the selected tab that corresponds to the given program.
	 * @param program The program to select.
	 */
	void setSelectedProgram(Program program) {
		if (currentProgram == program || !linkedProgramMap.containsKey(program)) {
			return;
		}

		// create the selected tab so that it will be used in setTabVisible()
		TabPanel panel = linkedProgramMap.get(program);
		panel = createProgramTab(program, true);
		linkedProgramMap.put(program, panel);

		clearSelectedProgram();
		currentProgram = program;
		setTabVisible(program);

		repaint();
		multiTabPlugin.programSelected(currentProgram);
	}

	int getTabCount() {
		return linkedProgramMap.size();
	}

	boolean containsProgram(Program program) {
		return linkedProgramMap.get(program) != null;
	}

	////////////////////////////////////////////////////////////
	// For JUnit tests

	int getVisibleTabCount() {
		return visibleTabList.size();
	}

	int getHiddenCount() {
		return hiddenTabList.size();
	}

	JPanel getTab(Object obj) {
		return linkedProgramMap.get(obj);
	}

	boolean isHidden(Object obj) {
		JPanel panel = linkedProgramMap.get(obj);
		if (panel != null) {
			return hiddenTabList.contains(panel);
		}
		return false;
	}

	////////////////////////////////////////////////////////////

	private TabPanel createProgramTab(final Program program, boolean isSelected) {
		final JPanel labelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 1));
		labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 10));

		JLabel nameLabel = new GDLabel();
		nameLabel.setIconTextGap(1);
		nameLabel.setName("objectName"); // junit access
		nameLabel.setFont(LABEL_FONT);
		Color foregroundColor = isSelected ? TEXT_SELECTION_COLOR : TEXT_NON_SELECTION_COLOR;
		nameLabel.setForeground(foregroundColor);

		labelPanel.add(nameLabel);

		JLabel iconLabel = new GIconLabel(isSelected ? CLOSE_ICON : EMPTY16_ICON);

		iconLabel.setToolTipText("Close");
		iconLabel.setName("Close"); // junit access

		MouseListener iconSwitcherMouseListener = new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent e) {
				if (e.getSource() == iconLabel) {
					iconLabel.setIcon(HIGHLIGHT_CLOSE_ICON);
				}
				else {
					iconLabel.setIcon(CLOSE_ICON);
				}
			}

			@Override
			public void mouseExited(MouseEvent e) {
				if (program == currentProgram) {
					iconLabel.setIcon(CLOSE_ICON);
				}
				else {
					iconLabel.setIcon(EMPTY16_ICON);
				}
			}
		};

		Color backgroundColor = isSelected ? BG_SELECTION_COLOR : BG_NON_SELECTION_COLOR;
		labelPanel.setBackground(backgroundColor);
		iconLabel.setBackground(backgroundColor);

		TabPanel tabPanel = null;
		if (isSelected) {
			tabPanel =
				new SelectedPanel(backgroundColor, program, nameLabel, labelPanel, iconLabel);
		}
		else {
			tabPanel = new TabPanel(backgroundColor, program, nameLabel, labelPanel, iconLabel);
		}
		tabPanel.refresh();

		GridBagLayout gbl = new GridBagLayout();
		tabPanel.setLayout(gbl);

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.anchor = GridBagConstraints.WEST;
		gbc.weightx = 1.0;
		gbl.setConstraints(labelPanel, gbc);
		tabPanel.add(labelPanel);

		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.anchor = GridBagConstraints.NORTHEAST;
		gbl.setConstraints(iconLabel, gbc);
		tabPanel.add(iconLabel);
		tabPanel.setBorder(new BottomlessBevelBorder());

		// this listener gets added to every component in the tab panel we are creating
		MouseListener tabSelectionMouseListener = new MouseAdapter() {

			// intentionally using mousePressed() and not mouseClicked() (see tracker 3415)
			@Override
			public void mousePressed(MouseEvent e) {
				// close the list window if the user has clicked outside of the window
				if (!(e.getSource() instanceof JList)) {
					hideListWindow();
				}

				if (e.isPopupTrigger()) {
					return; // allow popup triggers to show actions without changing tabs
				}

				// Tracker SCR 3605 - hitting 'X' to close tab doesn't work if tab is not selected
				if (e.getSource() == iconLabel) {
					doRemoveProgram(program);
					return;
				}

				if (!linkedProgramMap.containsKey(program) || currentProgram == program) {
					return; // object was removed or selection is the same
				}
				clearSelectedProgram();
				setSelectedProgram(program);
				hideListWindow();
				multiTabPlugin.programSelected(currentProgram);
			}
		};

		addMouseListener(tabPanel, tabSelectionMouseListener);
		addMouseListener(tabPanel, iconSwitcherMouseListener);

		linkedProgramMap.put(program, tabPanel);

		tabPanel.setMinimumSize(new Dimension(20, 20));
		return tabPanel;
	}

	private void clearSelectedProgram() {
		if (currentProgram == null) {
			return;
		}

		// resets the selected tab to be a 'normal' unselected tab
		TabPanel panel = linkedProgramMap.get(currentProgram);
		panel = createProgramTab(currentProgram, false);
		linkedProgramMap.put(currentProgram, panel);
	}

	private void doRemoveProgram(Program program) {
		JPanel panel = linkedProgramMap.get(program);
		if (panel == null) {
			return;
		}

		if (!multiTabPlugin.removeProgram(program)) {
			return;
		}

		removeProgram(program);
	}

	/**
	 * Remove the tab for the specified object.
	 * @param program object associated with a tab to remove
	 */
	void removeProgram(Program program) {
		highlightedProgram = null;
		JPanel panel = linkedProgramMap.get(program);
		if (panel == null) {
			return;
		}

		remove(panel);
		linkedProgramMap.remove(program);
		visibleTabList.remove(panel);
		hiddenTabList.remove(panel);
		if (program == currentProgram) {
			currentProgram = null;
		}
		packTabs(currentProgram);

		revalidate();
		repaint();

		hideListWindow();
	}

	void showProgramList() {
		// simply show the program list pop-up and let the user pick the program they want
		showListFromKeyboardAction(currentProgram);
	}

	void highlightNextProgram(boolean forwardDirection) {

		if (highlightedProgram != null) {
			highlightedProgram = getNextProgram(highlightedProgram, forwardDirection);
		}
		else if (listWindowIsShowing()) {
			highlightedProgram = getFirstProgramForDirection(forwardDirection);
			hideListWindow();
		}
		else {
			highlightedProgram = getNextProgram(currentProgram, forwardDirection);
		}

		// this is assumed to mean that the next program is in the hidden list
		if (highlightedProgram == null) {
			showList(showHiddenListLabel);
		}

		setHighlightedTab(highlightedProgram); // if this is null, then it will clear the display
		repaint(); // update to paint the highlighted tab
	}

	void selectHighlightedProgram() {
		setHighlightedTab(null); // if this is null, then it will clear the display
		if (highlightedProgram == null) {
			return;
		}

		setSelectedProgram(highlightedProgram);
		repaint();
	}

	private Program getFirstProgramForDirection(boolean forwardDirection) {
		int index = 0; // first item in forward direction
		if (!forwardDirection) {
			index = visibleTabList.size() - 1;
		}

		TabPanel panel = visibleTabList.get(index);
		return getProgramForPanel(panel);
	}

	private Program getNextProgram(Program startProgram, boolean forwardDirection) {
		TabPanel tabPanel = linkedProgramMap.get(startProgram);
		int index = getNextProgramIndex(visibleTabList.indexOf(tabPanel), forwardDirection);

		// next tab is visible, return it
		if (index >= 0) {
			TabPanel panel = visibleTabList.get(index);
			return getProgramForPanel(panel);
		}
		return null; // tab not visible
	}

	private int getNextProgramIndex(int visibleListIndex, boolean forwardDirection) {
		boolean hasHiddenPrograms = hiddenTabList.size() != 0;

		if (forwardDirection) {
			visibleListIndex++;
			if (visibleListIndex == visibleTabList.size()) { // reached the end, what to do next?
				return hasHiddenPrograms ? -1 : 0; // if no hidden tabs, then jump to the front
			}
			return visibleListIndex;
		}

		// going backwards
		visibleListIndex--;
		if (visibleListIndex < 0) { // was the first in list, what to do next?
			return hasHiddenPrograms ? -1 : visibleTabList.size() - 1; // no hidden tabs, circle around to the back
		}

		return visibleListIndex;
	}

	private Program getProgramForPanel(TabPanel panel) {
		Set<Entry<Program, TabPanel>> entrySet = linkedProgramMap.entrySet();
		for (Entry<Program, TabPanel> entry : entrySet) {
			if (entry.getValue() == panel) {
				return entry.getKey();
			}
		}

		return null; // shouldn't happen
	}

	private void setHighlightedTab(Program highlightedProgram) {
		// reset all colors
		Collection<TabPanel> values = linkedProgramMap.values();
		for (TabPanel tabPanel : values) {
			tabPanel.paintHighlightedColor(false);
		}

		TabPanel tabPanel = linkedProgramMap.get(highlightedProgram);
		if (tabPanel != null) {
			tabPanel.paintHighlightedColor(true);
		}
	}

	private void hideListWindow() {
		if (listWindow != null) {
			listWindow.setVisible(false);
			filterField.setText("");
		}
	}

	private void hideListWindowDueToFocusChange() {
		if (!ignoreFocus) {
			hideListWindow();
		}
	}

	/*testing*/ void setIgnoreFocus(boolean ignoreFocus) {
		this.ignoreFocus = ignoreFocus;
	}

	private void setTabVisible(Program program) {
		JPanel panel = linkedProgramMap.get(program);
		if (visibleTabList.contains(panel)) {
			return;
		}

		packTabs(program);
	}

	/**
	 * Make sure that the tabs fit in the given panel width.  If all of the tabs do not fit, then
	 * a subset will be used.  This method makes sure that the current program is always in the
	 * list of visible tabs.
	 * @param selectedProgram The currently selected program.
	 */
	private void packTabs(Program selectedProgram) {
		// get the number of tabs that will fit into the display and make sure the current proram's
		// tab is in that list
		List<TabPanel> newVisibleTabList = getTabsThatFitInView();
		newVisibleTabList = ensureCurrentProgramTabInView(selectedProgram, newVisibleTabList);

		// collect all of the hidden tabs
		Collection<TabPanel> allTabPanels = linkedProgramMap.values();
		List<TabPanel> newHiddenTabList = new ArrayList<>(allTabPanels);
		newHiddenTabList.removeAll(newVisibleTabList);

		// update visible tabs within this parent panel
		visibleTabList = newVisibleTabList;
		hiddenTabList = newHiddenTabList;
		highlightedProgram = null;

		super.removeAll(); // careful not to call our removeAll() here

		setVisible(allTabPanels.size() > 1);
		if (isVisible()) {
			for (JPanel panel : newVisibleTabList) {
				add(panel);
			}
			updateListLabel();
		}

		revalidate();
		repaint();
	}

	private List<TabPanel> getTabsThatFitInView() {
		int availableWidth = getWidth() - showHiddenListLabel.getPreferredSize().width;

		// get the number of tabs that will fit into the visible display
		List<TabPanel> newVisibleTabList = new ArrayList<>();
		List<TabPanel> allTabsList = new ArrayList<>(linkedProgramMap.values());
		int usedWidth = 0;
		for (TabPanel panel : allTabsList) {
			int currentTabWidth = panel.getPreferredSize().width;
			if ((availableWidth > 0) && (usedWidth + currentTabWidth > availableWidth)) {
				break;
			}
			usedWidth += currentTabWidth;
			newVisibleTabList.add(panel);
		}

		// check for the boundary condition where all elements would fit in the display if we 
		// don't show the label indicating tabs are hidden.  The boundary case is when there 
		// is only one hidden element that could potentially be put into the view
		if (allTabsList.size() - newVisibleTabList.size() == 1) {
			TabPanel lastPanel = allTabsList.get(allTabsList.size() - 1);
			if (usedWidth + lastPanel.getPreferredSize().width < getWidth()) {
				newVisibleTabList.add(lastPanel);
			}
		}

		return newVisibleTabList;
	}

	private List<TabPanel> ensureCurrentProgramTabInView(Program activeProgram,
			List<TabPanel> newVisibleTabList) {

		// no current tab to add
		TabPanel currentTabPanel = linkedProgramMap.get(activeProgram);
		if (currentTabPanel == null) {
			return newVisibleTabList;
		}

		// make sure the current tab is in the visible list
		if (newVisibleTabList.contains(currentTabPanel)) {
			return newVisibleTabList;
		}

		// make sure that the current space can at least fit the current tab
		int availablePanelWidth = getWidth();
		availablePanelWidth -= showHiddenListLabel.getWidth();

		int currentTabWidth = currentTabPanel.getPreferredSize().width;
		if (currentTabWidth > availablePanelWidth) {
			// not enough space for the current tab, so don't show any tabs
			newVisibleTabList.clear();
			return newVisibleTabList;
		}

		// get the spaced used by the tabs
		int usedWidth = 0;
		for (JPanel panel : newVisibleTabList) {
			usedWidth += panel.getPreferredSize().width;
		}

		// remove items from the end of the visible list until we have room for the current tab         
		for (int i = newVisibleTabList.size() - 1; i >= 0; i--) {
			TabPanel lastPanel = newVisibleTabList.remove(i);
			int width = lastPanel.getPreferredSize().width;
			usedWidth -= width;
			int newAvailableWidth = (availablePanelWidth - usedWidth);
			if (newAvailableWidth >= currentTabWidth) {
				// we have enough room now
				newVisibleTabList.add(currentTabPanel);
				break;
			}
		}

		return newVisibleTabList;
	}

	private void updateListLabel() {
		int hiddenCnt = hiddenTabList.size();
		if (hiddenCnt == 0) {
			remove(showHiddenListLabel);
			return;
		}

		// Make sure it stays to the right of the tabs
		remove(showHiddenListLabel);
		add(showHiddenListLabel);
		showHiddenListLabel.setText(Integer.toString(hiddenCnt));
	}

	private boolean listWindowIsShowing() {
		return listWindow != null && listWindow.isShowing();
	}

	private JLabel createLabel() {
		JLabel newLabel = new GDLabel(DEFAULT_HIDDEN_COUNT_STR, LIST_ICON, SwingConstants.LEFT);
		newLabel.setIconTextGap(0);
		newLabel.setFont(LIST_LABEL_FONT);
		newLabel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));
		newLabel.setToolTipText("Show Tab List");
		newLabel.setName("showList");
		newLabel.setBackground(new Color(255, 226, 213));

		defaultListLabelBorder = newLabel.getBorder();
		final Border hoverBorder = BorderFactory.createBevelBorder(BevelBorder.RAISED);
		newLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (listWindowIsShowing()) {
					hideListWindow();
					return;
				}

				showList(e.getComponent());
			}

			@Override
			public void mouseEntered(MouseEvent e) {
				// show a raised border, like a button (if the window is not already visible)
				if (listWindowIsShowing()) {
					return;
				}

				newLabel.setBorder(hoverBorder);
				newLabel.setOpaque(true);
			}

			@Override
			public void mouseExited(MouseEvent e) {
				// restore the button-like appearance to normal
				resetListLabelAppearance();
			}
		});

		newLabel.setPreferredSize(newLabel.getPreferredSize());

		return newLabel;
	}

	private void resetListLabelAppearance() {
		showHiddenListLabel.setBorder(defaultListLabelBorder);
		showHiddenListLabel.setOpaque(false);
	}

	private void showListFromKeyboardAction(Program startProgram) {
		if (!listWindowIsShowing()) {
			showList(null);
		}

		programListPanel.selectProgram(startProgram);
	}

	private void showList(Component source) {
		if (listWindow == null) {
			createListWindow();
		}
		else {
			programListPanel.setProgramLists(getProgramList(false), getProgramList(true));
		}
		listWindow.pack();

		setListLocationBelowLabel((JLabel) source);
		listWindow.setVisible(true);

		resetListLabelAppearance();

		programListPanel.requestFocus();
	}

	private void setListLocationBelowLabel(JLabel label) {

		Rectangle bounds = listWindow.getBounds();

		// no label implies we are launched from a keyboard event
		if (label == null) {

			Point centerPoint = WindowUtilities.centerOnComponent(getParent(), listWindow);
			bounds.setLocation(centerPoint);
			WindowUtilities.ensureOnScreen(getParent(), bounds);
			listWindow.setBounds(bounds);
			return;
		}

		// show the window just below the label that launched it
		Point p = label.getLocationOnScreen();
		int x = p.x;
		int y = p.y + label.getHeight() + 3;
		bounds.setLocation(x, y);

		// fixes problem where popup gets clipped when going across screens
		WindowUtilities.ensureOnScreen(label, bounds);
		listWindow.setBounds(bounds);
	}

	private void createListWindow() {
		Window parent = findParent();
		if (parent instanceof Dialog) {
			listWindow = new JDialog((Dialog) parent);
		}
		else {
			listWindow = new JDialog((Frame) parent);
		}
		listWindow.setUndecorated(true);

		listWindow.addWindowFocusListener(new WindowFocusListener() {
			@Override
			public void windowGainedFocus(WindowEvent e) {
				// don't care
			}

			@Override
			public void windowLostFocus(WindowEvent e) {
				hideListWindowDueToFocusChange();
			}
		});

		KeyListener listener = new KeyAdapter() {

			@Override
			public void keyPressed(KeyEvent e) {
				multiTabPlugin.keyTypedFromListWindow(e);
			}
		};

		programListPanel =
			new ProgramListPanel(getProgramList(false), getProgramList(true), multiTabPlugin);
		final JList<?> list = programListPanel.getList();
		filterField = programListPanel.getFilterField();
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				processWindowSelection();
			}
		});

		list.addKeyListener(listener);

		list.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					processWindowSelection();
				}
				else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					hideListWindow();
				}
			}
		});

		list.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent focusEvent) {
				// close the window when the user focuses another component 
				if (focusEvent.getOppositeComponent() != filterField) {
					hideListWindowDueToFocusChange();
				}
			}
		});

		filterField.addKeyListener(listener);

		filterField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if ((e.getKeyCode() == KeyEvent.VK_ENTER) ||
					(e.getKeyCode() == KeyEvent.VK_ESCAPE) || (e.getKeyCode() == KeyEvent.VK_UP) ||
					(e.getKeyCode() == KeyEvent.VK_DOWN)) {
					KeyboardFocusManager focusManager =
						KeyboardFocusManager.getCurrentKeyboardFocusManager();
					focusManager.redispatchEvent(list, e);
				}
			}
		});

		listWindow.getContentPane().add(programListPanel);

		parent.addWindowListener(new WindowAdapter() {
			@Override
			public void windowDeactivated(WindowEvent e) {
				if (!(e.getOppositeWindow() == listWindow)) {
					hideListWindowDueToFocusChange();
				}
			}
		});
		parent.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentMoved(ComponentEvent e) {
				hideListWindow();
			}
		});
		setActionMap();
	}

	private void processWindowSelection() {
		Program selectedProgram = programListPanel.getSelectedProgram();
		if (selectedProgram == null) {
			return; // no list selection
		}

		hideListWindow();
		if (selectedProgram == currentProgram) {
			return; // selection is already the active tab
		}

		setSelectedProgram(selectedProgram);
	}

	private List<Program> getProgramList(boolean getVisiblePrograms) {
		List<JPanel> panelList = null;
		if (getVisiblePrograms) {
			panelList = new ArrayList<>(visibleTabList);
		}
		else {
			panelList = new ArrayList<>(hiddenTabList);
		}

		List<Program> list = new ArrayList<>();
		Set<Entry<Program, TabPanel>> entrySet = linkedProgramMap.entrySet();
		for (Entry<Program, TabPanel> entry : entrySet) {
			JPanel panel = entry.getValue();
			if (panelList.contains(panel)) {
				list.add(entry.getKey());
			}
		}

		return list;
	}

	private Window findParent() {
		Container parent = getParent();
		while (!(parent instanceof Window) && !(parent instanceof JFrame)) {
			parent = parent.getParent();
		}
		return (Window) parent;
	}

	private void addMouseListener(Container c, MouseListener listener) {

		c.addMouseListener(listener);
		Component[] children = c.getComponents();
		for (Component element : children) {
			if (element instanceof Container) {
				addMouseListener((Container) element, listener);
			}
			else {
				element.addMouseListener(listener);
			}
		}
	}

	private void setActionMap() {
		AbstractAction escAction = new AbstractAction("Exit Window") {
			@Override
			public void actionPerformed(ActionEvent e) {
				hideListWindow();
			}
		};

		JComponent rootPane = listWindow.getRootPane();
		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
		KeyBindingUtils.registerAction(rootPane, ks, escAction, JComponent.WHEN_IN_FOCUSED_WINDOW);
	}

	private String getProgramName(Program program) {
		String name = program.toString();
		if (multiTabPlugin != null) {
			name =
				(multiTabPlugin.isChanged(program) ? "*" : " ") + multiTabPlugin.getName(program);
		}
		return name;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class TabPanel extends JPanel {
		private Color defaultBackgroundColor;
		protected final JLabel nameLabel;
		protected final JPanel labelPanel;
		protected final JLabel iconLabel;
		private final Program program;

		private TabPanel(Color backgroundColor, Program program, JLabel nameLabel,
				JPanel labelPanel, JLabel iconLabel) {
			this.defaultBackgroundColor = backgroundColor;
			this.program = program;
			this.nameLabel = nameLabel;
			this.labelPanel = labelPanel;
			this.iconLabel = iconLabel;
		}

		void refresh() {
			String name = getProgramName(program);
			ProjectLocator projectLocator = program.getDomainFile().getProjectLocator();
			if (projectLocator != null && projectLocator.isTransient()) {
				nameLabel.setIcon(TRANSIENT_ICON);
			}
			else {
				nameLabel.setIcon(EMPTY8_ICON);
			}
			nameLabel.setText(name);
			String toolTip = multiTabPlugin != null ? multiTabPlugin.getToolTip(program) : null;
			nameLabel.setToolTipText(toolTip);
		}

		void paintHighlightedColor(boolean paintHighlight) {
			Color newBackgroundColor = defaultBackgroundColor;
			if (paintHighlight) {
				newBackgroundColor = HIGHLIGHTED_TAB_COLOR;
			}
			setBackground(newBackgroundColor);
			nameLabel.setBackground(newBackgroundColor);
			labelPanel.setBackground(newBackgroundColor);
			iconLabel.setBackground(newBackgroundColor);
		}
	}

	// a panel that paints below it's bounds in order to connect the panel and the border 
	// below it visually
	private class SelectedPanel extends TabPanel {
		private SelectedPanel(Color backgroundColor, Program program, JLabel nameLabel,
				JPanel labelPanel, JLabel iconLabel) {
			super(backgroundColor, program, nameLabel, labelPanel, iconLabel);
			setBorder(new BottomlessBevelBorder());

			// color our widgets special
			setBackground(BG_SELECTION_COLOR);
			labelPanel.setBackground(BG_SELECTION_COLOR);
			nameLabel.setForeground(TEXT_SELECTION_COLOR);
			iconLabel.setBackground(BG_SELECTION_COLOR);
			iconLabel.setIcon(CLOSE_ICON);
		}

		@Override
		protected void paintComponent(Graphics g) {
			Shape saveClip = g.getClip();
			Color oldColor = g.getColor();
			Rectangle bounds = saveClip.getBounds();
			g.setClip(bounds.x, bounds.y, bounds.width, getHeight() + 2);
			g.setColor(getBackground());
			g.fillRect(0, 0, getWidth(), getHeight() + 2);
			g.setColor(oldColor);
			g.setClip(saveClip);
			super.paintComponent(g);
		}

		@Override
		void paintHighlightedColor(boolean paintHighlight) {
			super.paintHighlightedColor(paintHighlight);
			Color foreground = Color.WHITE;
			if (paintHighlight) {
				foreground = Color.BLACK;
			}

			// this tab is selected, so change the foreground to be readable
			nameLabel.setForeground(foreground);
		}
	}

	// This class doesn't paint the bottom border in order to make the object appear to be 
	// connected to the component below.  This class also paints its side borders below its 
	// bounds for the same reason.
	class BottomlessBevelBorder extends BevelBorder {
		public BottomlessBevelBorder() {
			super(RAISED);
		}

		@Override
		// overridden to reduce the space below, since there is no component	    
		public Insets getBorderInsets(Component c) {
			Insets borderInsets = super.getBorderInsets(c);
			borderInsets.bottom = 0;
			return borderInsets;
		}

		@Override
		protected void paintRaisedBevel(Component c, Graphics g, int x, int y, int width,
				int height) {
			Color oldColor = g.getColor();
			int h = height;
			int w = width;

			g.translate(x, y);

			Shape saveClip = g.getClip();
			Rectangle bounds = saveClip.getBounds();
			g.setClip(bounds.x, bounds.y, bounds.width, getHeight() + 2);

			g.setColor(getShadowOuterColor(c));
			g.drawLine(0, 0, 0, h); // left outer
			g.setColor(getHighlightOuterColor(c));
			g.drawLine(1, 0, w - 2, 0); // upper outer

			g.setColor(getHighlightInnerColor(c));
			g.drawLine(1, 1, 1, h); // left inner
			g.drawLine(2, 1, w - 3, 1); // upper inner

			// bottom outer
			g.setColor(getShadowOuterColor(c));
			g.drawLine(w - 1, 0, w - 1, h); // right outer

			// bottom inner
			g.setColor(getShadowInnerColor(c));
			g.drawLine(w - 2, 1, w - 2, h); // right inner

			g.setClip(saveClip);

			g.translate(-x, -y);
			g.setColor(oldColor);

		}
	}

	// a bevel border to paint only it's bottom edge, but with the highlight normally found at
	// the top edge
	class BottomOnlyBevelBorder extends BevelBorder {
		public BottomOnlyBevelBorder() {
			super(RAISED);
		}

		@Override
		protected void paintRaisedBevel(Component c, Graphics g, int x, int y, int width,
				int height) {
			Color oldColor = g.getColor();
			int h = height;
			int w = width;

			g.translate(x, y);

			// bottom outer
			g.setColor(getHighlightOuterColor(c));
			g.drawLine(0, h - 1, w - 1, h - 1);

			// bottom inner         
			g.setColor(getShadowInnerColor(c));

			g.translate(-x, -y);
			g.setColor(oldColor);

		}
	}
}
