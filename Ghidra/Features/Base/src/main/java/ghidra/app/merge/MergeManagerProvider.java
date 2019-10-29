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
package ghidra.app.merge;

import java.awt.*;
import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.options.editor.ButtonPanelFactory;
import docking.util.image.ToolIconURL;
import docking.widgets.OptionDialog;
import docking.widgets.label.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.format.FieldHeaderComp;
import ghidra.app.util.viewer.format.FieldHeaderLocation;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;

/**
 * Component that displays merge components as needed.
 * 
 * 
 */
class MergeManagerProvider extends ComponentProviderAdapter {

	final static String DEFAULT_ID = "Default Panel";
	private final static String DEFAULT_INFO = "Merge programs in progress...";

	private MergeManagerPlugin plugin;
	private JComponent currentComponent;
	private JLabel nameLabel;
	private CardLayout cardLayout;
	private JPanel defaultPanel;
	private JPanel conflictPanel;
	private PhaseProgressPanel phasePanel;
	private JButton applyButton;
	private JButton cancelButton;
	private boolean wasCanceled;

	private ImageIcon MERGE_ICON = ResourceManager.loadImage("images/Merge.png");
	private JPanel mainPanel;

	public MergeManagerProvider(MergeManagerPlugin plugin, String title) {
		super(plugin.getTool(), "Merge Manager", plugin.getName());
		this.plugin = plugin;
		setTitle(title);
		setDefaultWindowPosition(WindowPosition.TOP);
		setIcon(MERGE_ICON);
		tool.setIconURL(new ToolIconURL("Merge.png"));
		setHelpLocation(new HelpLocation(HelpTopics.REPOSITORY, "Merge_Manager"));
		create();
		tool.addComponentProvider(this, true);
		tool.showComponentHeader(this, false);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		// TODO Put this someplace else that makes better sense. (Maybe in the plugin?)
		MergeManager mergeManager = plugin.getMergeManager();
		if (event != null && event.getSource() instanceof FieldHeaderComp) {
			FieldHeaderComp comp = (FieldHeaderComp) event.getSource();
			FieldHeaderLocation fieldHeaderLocation = comp.getFieldHeaderLocation(event.getPoint());
			return createContext(fieldHeaderLocation);

		}
		if (mergeManager instanceof ProgramMultiUserMergeManager) {
			ProgramMultiUserMergeManager programMergeManager =
				(ProgramMultiUserMergeManager) mergeManager;
			Navigatable navigatable = programMergeManager.navigatable;
			if (currentComponent instanceof ListingMergePanel) {
				// Set the program location within the context so it is from the listing panel
				// that is being clicked. Actions should use the location to know which of the
				// 4 programs or listings is in the current context.
				ListingMergePanel listingMergePanel = (ListingMergePanel) currentComponent;
				Object actionContext = listingMergePanel.getActionContext(event);
				if (actionContext instanceof ProgramLocation) {
					ListingActionContext listingActionContext = new ListingActionContext(this,
						navigatable, (ProgramLocation) actionContext);
					return listingActionContext;
				}
			}
			ProgramLocation programLocation = navigatable.getLocation();
			ListingActionContext listingActionContext =
				new ListingActionContext(this, navigatable, programLocation);
			return listingActionContext;
		}
		return null;
	}

	/**
	 * Enables/disables the Apply button at the bottom of the merge tool.
	 * The Apply button is for applying conflicts.
	 * @param state true means enable the button. false means disable it.
	 */
	void setApplyEnabled(boolean state) {
		applyButton.setEnabled(state);
		if (state) { // Set focus to apply button when it gets enabled.
			applyButton.requestFocus();
		}
	}

	/**
	 * Defines and displays a component for resolving merge conflicts.
	 * @param component the component
	 * @param componentID the identifier for this component
	 */
	void setMergeComponent(JComponent component, String componentID) {
		if (currentComponent != null) {
			cardLayout.removeLayoutComponent(currentComponent);
		}
		currentComponent = component;
		conflictPanel.add(component, componentID);
		cardLayout.show(conflictPanel, componentID);
	}

	/**
	 * Removes use of a component for resolving merge conflicts.
	 * @param component the component
	 */
	void removeMergeComponent(JComponent component) {
		cardLayout.removeLayoutComponent(component);
		conflictPanel.remove(component);
	}

	/**
	 * Sets the merge description at the top of the merge tool.
	 * @param description the description
	 */
	void updateMergeDescription(String description) {
		nameLabel.setText(description);
	}

	/**
	 * Displays the default information in the merge tool.
	 */
	void showDefaultComponent() {
		cardLayout.show(conflictPanel, DEFAULT_ID);
	}

	void dispose() {
		tool.showComponentProvider(this, false);
		tool.removeComponentProvider(this);
//		plugin = null;
//		tool = null;
	}

	boolean mergeWasCanceled() {
		return wasCanceled;
	}

	private void applyCallback() {
		plugin.getMergeManager().apply();
		setApplyEnabled(false);
	}

	void cancelCallback(boolean force) {

		boolean cancel = force;
		if (!force) {
			int choice =
				OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Confirm Cancel Merge",
					"Warning!  Cancel causes the entire merge process to be canceled.\n" +
						"Do you want to cancel the Merge Process?");
			cancel = choice == OptionDialog.OPTION_ONE;
		}

		if (cancel) {
			wasCanceled = true;
			MergeManager mergeManager = plugin.getMergeManager();
			if (mergeManager != null) {
				mergeManager.cancel();
			}
		}
	}

	private void create() {
		mainPanel = new JPanel();
		cardLayout = new CardLayout();
		conflictPanel = new JPanel(cardLayout);

		mainPanel.setLayout(new BorderLayout(0, 10));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		nameLabel = new GDLabel("Merge Programs", SwingConstants.LEFT);

		JPanel iconPanel = new JPanel();
		new BoxLayout(iconPanel, BoxLayout.X_AXIS);
		iconPanel.add(Box.createHorizontalStrut(5));
		iconPanel.add(new GIconLabel(MERGE_ICON));
		iconPanel.add(Box.createHorizontalStrut(5));
		iconPanel.add(nameLabel);

		JPanel imagePanel = new JPanel(new BorderLayout());
		imagePanel.add(iconPanel, BorderLayout.WEST);

		mainPanel.add(imagePanel, BorderLayout.NORTH);
		mainPanel.add(conflictPanel, BorderLayout.CENTER);

		mainPanel.add(createButtonPanel(), BorderLayout.SOUTH);
		createDefaultPanel();
		cardLayout.show(conflictPanel, DEFAULT_ID);
		Dimension d = conflictPanel.getPreferredSize();
		mainPanel.setPreferredSize(new Dimension(d.width, d.height + 20));
	}

	private JPanel createButtonPanel() {
		applyButton = new JButton("Apply");
		applyButton.addActionListener(e -> applyCallback());
		applyButton.setEnabled(false);
		applyButton.setToolTipText("Apply conflict resolution");

		cancelButton = new JButton("Cancel");
		cancelButton.addActionListener(e -> cancelCallback(false));

		JPanel panel = ButtonPanelFactory.createButtonPanel(
			new JButton[] { applyButton, cancelButton }, ButtonPanelFactory.X_AXIS);

		return panel;
	}

	// Creates the default panel that shows the phases along with the current phase progress.
	private void createDefaultPanel() {
		defaultPanel = new JPanel(new VerticalLayout(5));
		defaultPanel.setName(DEFAULT_ID);

		MergeProgressPanel progressPanel = plugin.getMergeManager().getMergeProgressPanel();
		phasePanel = new PhaseProgressPanel("Progress In Current Phase");

		defaultPanel.add(progressPanel); // panel with each phase and their status indicators.
		defaultPanel.add(new GLabel(" ")); // Blank separator label.
		defaultPanel.add(phasePanel); // panel for the current phase's progress and message.
		conflictPanel.add(defaultPanel, DEFAULT_ID);
		conflictPanel.setPreferredSize(new Dimension(610, 500));
		cardLayout.show(conflictPanel, DEFAULT_ID);
	}

	/**
	 * Sets the percentage of the progress meter that is filled in for the current phase progress area.
	 * @param currentPercentProgress the percentage of the progress bar to fill in from 0 to 100.
	 */
	public void setCurrentProgress(int currentPercentProgress) {
		phasePanel.setProgress(currentPercentProgress);
	}

	/**
	 * Sets the title for the current phase progress area.
	 * @param newTitle the new title
	 */
	public void updateProgressTitle(String newTitle) {
		phasePanel.setTitle(newTitle);
	}

	/**
	 * Sets the message below the progress meter in the current phase progress area.
	 * @param message the new text message to display. If null, then the default message is displayed.
	 */
	public void updateProgressDetails(String message) {
		if (message == null) {
			message = DEFAULT_INFO;
		}
		phasePanel.setMessage(message);
	}

}
