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
package ghidra.app.plugin.core.diff;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;

import javax.swing.*;
import javax.swing.text.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.checkbox.GCheckBox;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

/**
 * The DiffDetailsProvider is used to view the differences for an address or
 * code unit address range.
 */
public class DiffDetailsProvider extends ComponentProviderAdapter {
	public static final String DIFF_DETAILS_HIDDEN_ACTION = "Diff Details Hidden";
	public static final String AUTO_UPDATE_CHECK_BOX = "Auto Update Check Box";
	public static final String FILTER_DIFFS_CHECK_BOX = "Filter Diffs Check Box";
	public static final String DIFF_DETAILS_TEXT_AREA = "Diff Details Text Area";
	public static final String DIFF_DETAILS_PANEL = "Diff Location Details Panel";
	public static final ImageIcon ICON = ResourceManager.loadImage("images/xmag.png");
	public static final ImageIcon REFRESH_ICON = Icons.REFRESH_ICON;
	public static final String TITLE = "Diff Details";

	private ProgramDiffPlugin plugin;
	private JTextPane textPane;
	private StyledDocument doc;
	private JCheckBox filterDiffsCB;
	private JCheckBox autoUpdateCB;
	private boolean filterDiffs = false;
	private boolean autoUpdate = false;
	private JComponent detailsPanel;
	private ArrayList<ActionListener> listenerList = new ArrayList<>();
	private ProgramLocation p1DetailsLocation;
	private AddressSetView detailsAddrSet;
	private boolean isDisplayed = false;

	private SwingUpdateManager updateManager;
	private ProgramLocation currentLocation;

	/**
	 * @param plugin
	 */
	public DiffDetailsProvider(ProgramDiffPlugin plugin) {
		super(plugin.getTool(), "Diff Location Details", plugin.getName());
		setTitle(TITLE);
		this.plugin = plugin;
		setIcon(ICON);
		setTransient();
		setWindowMenuGroup("Diff");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setHelpLocation(new HelpLocation("Diff", "Diff_Location_Details"));
		detailsPanel = createDiffDetailsPanel();
		detailsPanel.setName(DIFF_DETAILS_PANEL);
		setAutoUpdate(true);
		setFilterDiffs(false);
		setUpRefreshDetailsUpdateManager();
	}

	/**
	 * @param selected
	 */
	public void setAutoUpdate(boolean selected) {
		autoUpdateCB.setSelected(selected);
		autoUpdate = selected;
	}

	/**
	 * @param selected
	 */
	public void setFilterDiffs(boolean selected) {
		filterDiffsCB.setSelected(selected);
		filterDiffs = selected;
	}

	public void addActions() {
		DockingAction refreshDetailsAction =
			new DockingAction("Refresh Diff Details", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					refreshDetails(plugin.getCurrentLocation());
				}
			};

		refreshDetailsAction.setDescription(
			"Refresh the details to show any differences at the current location.");
		refreshDetailsAction.setEnabled(true);

		refreshDetailsAction.setToolBarData(new ToolBarData(REFRESH_ICON, "Diff"));
		refreshDetailsAction.setHelpLocation(
			new HelpLocation(HelpTopics.DIFF, "Refresh Diff Details"));
		plugin.getTool().addLocalAction(this, refreshDetailsAction);
//		plugin.getTool().addLocalAction(this, new DiffIgnoreAllAction(this));
	}

	/**
	 *  Create the automatically update checkbox for diff details.
	 */
	private void createAutoUpdateCheckBox() {

		autoUpdateCB = new GCheckBox("Automatically Update Details", false);
		autoUpdateCB.setName(AUTO_UPDATE_CHECK_BOX);
		autoUpdateCB.addActionListener(e -> {
			autoUpdate = autoUpdateCB.isSelected();
			if (autoUpdate) {
				refreshDetails(plugin.getCurrentLocation());
			}
		});

	}

	/**
	 *  Creates the only show the filtered differences checkbox for diff details
	 */
	private void createFilterDiffsCheckBox() {

		filterDiffsCB = new GCheckBox("Only Show Expected Difference Types", false);
		filterDiffsCB.setName(FILTER_DIFFS_CHECK_BOX);
		filterDiffsCB.addActionListener(e -> {
			filterDiffs = filterDiffsCB.isSelected();
			if (autoUpdateCB.isSelected()) {
				refreshDetails(plugin.getCurrentLocation());
			}
		});

	}

	/**
	 * @param p1Location
	 */
	protected void locationChanged(ProgramLocation p1Location) {
		if (isDisplayed && autoUpdate) {
			refreshDetails(p1Location);
		}
	}

	/**
	 * Refreshes the displayed Diff Details for the indicated program location address.
	 * @param p1Location This should be a program1 location.
	 */
	void refreshDetails(ProgramLocation p1Location) {
		if (p1Location == null) {
			return;
		}
		currentLocation = p1Location;
		updateManager.update();
	}

	/**
	 * Establishes a swing update manager that is used to refresh the DiffDetails.
	 */
	private void setUpRefreshDetailsUpdateManager() {
		updateManager = new SwingUpdateManager(100, 4000, () -> doRefreshDetails(currentLocation));
	}

	/**
	 * Refreshes the displayed Diff Details for the indicated program location address.
	 * @param p1Location This should be a program1 location.
	 */
	private void doRefreshDetails(ProgramLocation p1Location) {
		if (p1Location == null) {
			return;
		}
		// Do nothing if not visible.
		if (!isDisplayed) {
			return;
		}

		Program p1 = p1Location.getProgram();
		if (p1 != plugin.getFirstProgram() && p1 != plugin.getSecondProgram()) {
			return; // If this location isn't for our Diff then ignore it. May be switching program tabs.
		}
		if (p1DetailsLocation != p1Location) {
			p1DetailsLocation = p1Location;
		}
		AddressSetView newAddrSet = getDetailsAddressSet(p1DetailsLocation);

		if (newAddrSet == null) {
			setDocumentToErrorMessage("Must have a second program open to determine Diff details.");
			return;
		}

		if (!newAddrSet.equals(detailsAddrSet)) {
			detailsAddrSet = newAddrSet;
		}
		Address p1Address = p1DetailsLocation.getAddress();
		try {
			if (filterDiffs) {
				getFilteredDiffDetails(p1Address);
			}
			else {
				getDiffDetails(p1Address);
			}
		}
		catch (ConcurrentModificationException e) {
			setDocumentToErrorMessage(
				"Failed to determine Diff Details due to concurrent program changes.\n" +
					"This may be caused by background analysis activity.\n" +
					" *** Press the Refresh button to update *** ");

			// The program is being modified while this is trying to get the details.
			// If we want to automatically try again, this would need to re-issue the update
			// by calling updateManager.updateLater() here.
		}
	}

	private void setDocumentToErrorMessage(String message) {
		try {
			doc.remove(0, doc.getLength());
			doc.insertString(0, message, new SimpleAttributeSet());
			textPane.setCaretPosition(0);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	/**
	 * Gets the Diff Details at the indicated address
	 * @param p1Address the program1 address
	 * @throws ConcurrentModificationException if analysis is modifying the program.
	 */
	private void getDiffDetails(Address p1Address) {
		plugin.addDiffDetails(p1Address, doc);
		textPane.setCaretPosition(0);
	}

	private void getFilteredDiffDetails(Address p1Address) {
		plugin.addFilteredDiffDetails(p1Address, plugin.getDiffController().getDiffFilter(), doc);
		textPane.setCaretPosition(0);
	}

	/**
	 * Gets the address set where detailed differences will be determined for details at the
	 * indicated address. An address set is returned since the indicated address may be in different
	 * sized code units in each of the two programs.
	 * @param p1Location the program location in program1 where details are desired.
	 * @return the address set for code units containing that address within the programs being 
	 * compared to determine differences.
	 * Otherwise null if a diff of two programs isn't being performed.
	 */
	private AddressSetView getDetailsAddressSet(ProgramLocation p1Location) {
		Address p1Address = p1Location.getAddress();
		return plugin.getDetailsAddressSet(p1Address);
	}

	/**
	 *  Create a panel for the Diff details and auto update checkbox.
	 */
	private JPanel createDiffDetailsPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setPreferredSize(new Dimension(600, 400));
		JScrollPane scrolledDetails = createDetailsPane();
		panel.add(scrolledDetails, BorderLayout.CENTER);
		createAutoUpdateCheckBox();
		createFilterDiffsCheckBox();
		JPanel bottomPanel = new JPanel();
		bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.X_AXIS));
		bottomPanel.add(Box.createHorizontalGlue());
		bottomPanel.add(autoUpdateCB);
		bottomPanel.add(Box.createHorizontalStrut(10));
		bottomPanel.add(filterDiffsCB);
		bottomPanel.add(Box.createHorizontalGlue());
		panel.add(bottomPanel, BorderLayout.SOUTH);
		return panel;
	}

	private JScrollPane createDetailsPane() {
		Font font = new Font("Monospaced", Font.PLAIN, 12);
		textPane = new JTextPane();
		doc = textPane.getStyledDocument();
		textPane.setName(DIFF_DETAILS_TEXT_AREA);
		textPane.setEditable(false);
		textPane.setMargin(new Insets(5, 5, 5, 5));
		textPane.setFont(font);
		textPane.setOpaque(true);
		textPane.setCaretPosition(0);
		JScrollPane scrolledDetails = new JScrollPane(textPane);
		JViewport vp = scrolledDetails.getViewport();
		vp.add(textPane);
		return scrolledDetails;
	}

	StyledDocument getStyledDocument() {
		return doc;
	}

	@Override
	public void componentHidden() {
		for (int i = 0; i < listenerList.size(); i++) {
			ActionListener listener = listenerList.get(i);
			listener.actionPerformed(new ActionEvent(this, 0, DIFF_DETAILS_HIDDEN_ACTION));
		}
		isDisplayed = false;
		p1DetailsLocation = null;
	}

	@Override
	public void componentShown() {
		isDisplayed = true;
		refreshDetails(plugin.getProgramLocation());
	}

	@Override
	public void closeComponent() {
		// overridden to not remove this transient provider
		plugin.getTool().showComponentProvider(this, false);
	}

	@Override
	public JComponent getComponent() {
		return detailsPanel;
	}

	Plugin getPlugin() {
		return plugin;
	}

	public void addActionListener(ActionListener listener) {
		listenerList.add(listener);
	}

	public void removeActionListener(ActionListener listener) {
		listenerList.remove(listener);
	}
}
