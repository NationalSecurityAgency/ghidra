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
package docking.wizard;

import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.IOException;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import ghidra.util.*;
import resources.ResourceManager;

/**
 * A dialog that controls the panels for going to "Next" and "Previous" in some
 * process that the user is being led through.
 */
public class WizardManager extends DialogComponentProvider implements WizardPanelListener {
	/**Default text for the 'finish' button*/
	public static final String FINISH = "Finish";
	/**Default text for the 'next' button*/
	public static final String NEXT = "Next >>";
	/**Default text for the 'back' button*/
	public static final String BACK = "<< Back";

	private final static String INIT_TITLE = "<< untitled >>";

	private PanelManager panelMgr;
	private WizardPanel currWizPanel;
	private JButton backButton;
	private JButton nextButton;
	private JButton finishButton;
	private JLabel titleLabel;
	private JPanel mainJPanel;
	private JScrollPane scrollPane;
	private JPanel currJPanel;

	/**
	 * Constructor
	 * @param title title of the dialog
	 * @param modal true if the wizard should be modal
	 * @param pmgr object that knows about the next and previous panels
	 */
	public WizardManager(String title, boolean modal, PanelManager pmgr) {
		this(title, modal, pmgr, null);
	}

	/**
	 * Constructor
	 * @param title title of the dialog
	 * @param modal true if the wizard should be modal
	 * @param pmgr object that knows about the next and previous panels
	 * @param wizardIcon icon to use for this dialog
	 */
	public WizardManager(String title, boolean modal, PanelManager pmgr, Icon wizardIcon) {
		super(title, modal);
		init(pmgr, wizardIcon);
	}

	/**
	 * @see java.awt.Window#dispose()
	 */
	public void dispose() {
		if (currWizPanel != null) {
			currWizPanel.removeWizardPanelListener(this);
		}
		close();
	}

	/**
	 * 
	 * @see docking.wizard.WizardPanelListener#validityChanged()
	 */
	@Override
	public void validityChanged() {
		clearStatusText();
		enableButtons();
	}

	/**
	 * Returns the current status message being displayed in this dialog.
	 * @return the current status message being displayed in this dialog
	 */
	public String getStatusMessage() {
		return getStatusText();
	}

	/** 
	 * @see docking.wizard.WizardPanelListener#setStatusMessage(String)
	 */
	@Override
	public void setStatusMessage(final String msg) {
		if (SwingUtilities.isEventDispatchThread()) {
			setStatusText(msg);
		}
		else {
			Runnable r = () -> setStatusText(msg);
			SwingUtilities.invokeLater(r);
		}
	}

	/**
	 * Display this dialog.
	 */
	public void showWizard() {
		showWizard(null);
	}

	/**
	 * Display this dialog and parent it to the given component.
	 * @param parent parent
	 */
	public void showWizard(Component parent) {
		panelMgr.initialize();

		WizardPanel nextPanel = null;
		try {
			nextPanel = panelMgr.getNextPanel();
			if (nextPanel == null) {
				Msg.showError(this, parent, getTitle() + " Error", "Failed to render wizard panel");
				return;
			}
		}
		catch (IllegalPanelStateException e) {
			handleIllegalStateException(e, true);
			return;
		}

		setCurrentPanel(nextPanel);

		DockingWindowManager.showDialog(parent, this);
	}

	/**
	 * Notification that the wizard process is complete.
	 * @param success status of the process
	 */
	public void completed(boolean success) {

		if (!success) {
			return;
		}

		SystemUtilities.runSwingNow(() -> {
			close();
		});
	}

	/**
	 * Enable the next, previous, and finish buttons according to the
	 * panel manager for this dialog. The panel manager is the object that
	 * knows the steps in the process and what buttons should be
	 * enabled.
	 */
	public void enableNavigation() {
		enableButtons();
		super.setCancelEnabled(true);
	}

	/**
	 * Disable the back, next, finish, and cancel buttons.
	 */
	public void disableNavigation() {
		backButton.setEnabled(false);
		nextButton.setEnabled(false);
		finishButton.setEnabled(false);
		super.setCancelEnabled(false);
	}

	@Override
	protected void cancelCallback() {
		panelMgr.cancel();
		close();
	}

	private void init(PanelManager pmgr, Icon wizardIcon) {
		this.panelMgr = pmgr;
		this.panelMgr.setWizardManager(this);

		Dimension panelSize = panelMgr.getPanelSize();
		currJPanel = new JPanel();
		currJPanel.setPreferredSize(panelSize);
		currJPanel.setMinimumSize(panelSize);

		scrollPane = new JScrollPane();
		scrollPane.setBorder(BorderFactory.createEmptyBorder());
		scrollPane.setPreferredSize(panelSize);
		scrollPane.setMinimumSize(panelSize);

		scrollPane.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateScrollPaneBorder(currJPanel);
			}
		});

		titleLabel = (wizardIcon == null ? new GDLabel(INIT_TITLE)
				: new GDLabel(INIT_TITLE, wizardIcon, SwingConstants.TRAILING));

		EmptyBorderButton helpButton =
			new EmptyBorderButton(ResourceManager.loadImage("images/information.png"));
		helpButton.setToolTipText("Help (F1)");
		helpButton.addActionListener(
			e -> DockingWindowManager.getHelpService().showHelp(rootPanel, false, rootPanel));

		JPanel titlePanel = new JPanel();
		titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.X_AXIS));
		titlePanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEtchedBorder(),
			BorderFactory.createEmptyBorder(5, 5, 5, 5)));
		titlePanel.add(titleLabel);
		titlePanel.add(Box.createHorizontalGlue());
		titlePanel.add(helpButton);

		mainJPanel = new JPanel(new BorderLayout());
		mainJPanel.add(titlePanel, BorderLayout.NORTH);
		mainJPanel.add(scrollPane, BorderLayout.CENTER);

		backButton = new JButton(BACK);
		backButton.setMnemonic('B');
		nextButton = new JButton(NEXT);
		nextButton.setMnemonic('N');
		finishButton = new JButton(FINISH);
		finishButton.setMnemonic('F');

		backButton.addActionListener(evt -> back());
		nextButton.addActionListener(evt -> next());
		finishButton.addActionListener(evt -> finish());

		addButton(backButton);
		addButton(nextButton);
		addButton(finishButton);
		addCancelButton();

		setDefaultButton(nextButton);

		addWorkPanel(mainJPanel);
		setRememberLocation(false);
		setRememberSize(false);
	}

	private boolean handleIllegalStateException(IllegalPanelStateException e, boolean alwaysClose) {
		Throwable cause = e.getCause();
		if (cause == null) {
			cause = e;
		}
		boolean closeOnError = true;
		if (!alwaysClose && cause instanceof IOException) {
			closeOnError = false;
			try {
				panelMgr.initialize();
				setCurrentPanel(panelMgr.getInitialPanel());
				Msg.showError(this, null, getTitle() + " Error", cause.getMessage());
				enableNavigation();
			}
			catch (IllegalPanelStateException e1) {
				closeOnError = true; // close if unable to display first panel
			}
		}
		if (closeOnError) {
			if (cause instanceof IOException) {
				Msg.showError(this, null, getTitle() + " Error", cause.getMessage());
			}
			else {
				String message = cause.getMessage();
				message = message != null ? message : cause.getClass().getSimpleName();
				Msg.showError(this, null, getTitle() + " Error", message, cause);
			}
			close();
			return false;
		}
		return true;
	}

	/**
	 * Programmatically move the wizard back one panel.
	 * Simulates the user clicking on the 'back' button.
	 * Returns true if not on the first panel.
	 * @return true if not on the first panel
	 */
	public boolean back() {
		if (backButton.isEnabled()) {
			try {
				setCurrentPanel(panelMgr.getPreviousPanel());
			}
			catch (IllegalPanelStateException e) {
				if (!handleIllegalStateException(e, false)) {
					return false;
				}
			}
			String msg = panelMgr.getStatusMessage();
			if (msg != null) {
				setStatusMessage(msg);
			}
			return true;
		}
		return false;
	}

	/**
	 * Programmatically move the wizard forward one panel.
	 * Simulates the user clicking on the 'next' button.
	 * Returns true if not on the last panel.
	 * @return true if not on the last panel
	 */
	public boolean next() {
		if (nextButton.isEnabled()) {
			try {
				setCurrentPanel(panelMgr.getNextPanel());
			}
			catch (IllegalPanelStateException e) {
				if (!handleIllegalStateException(e, false)) {
					return false;
				}
			}
			String msg = panelMgr.getStatusMessage();
			if (msg != null) {
				setStatusMessage(msg);
			}
			return true;
		}
		return false;
	}

	/**
	 * Places focus on the 'next' button.
	 */
	public void focusNext() {
		nextButton.requestFocus();
	}

	/**
	 * Places focus on the 'finish' button.
	 */
	public void focusFinish() {
		finishButton.requestFocus();
		setDefaultButton(finishButton);
	}

	/**
	 * Programmatically finished the wizard task.
	 * Returns true if the wizard can finish.
	 * @return true if the wizard can finish
	 */
	public boolean finish() {
		if (finishButton.isEnabled()) {
			try {
				panelMgr.finish();
			}
			catch (IllegalPanelStateException e) {
				if (!handleIllegalStateException(e, false)) {
					return false;
				}
			}
			String msg = panelMgr.getStatusMessage();
			if (msg != null) {
				setStatusMessage(msg);
			}
			return true;
		}
		return false;
	}

	/**
	 * Returns the current wizard panel.
	 * @return the current wizard panel
	 */
	public WizardPanel getCurrentWizardPanel() {
		return currWizPanel;
	}

	/**
	 * Sets the current wizard panel.
	 * @param p the current panel
	 */
	private void setCurrentPanel(WizardPanel p) {
		if (currWizPanel != null) {
			currWizPanel.removeWizardPanelListener(this);
		}
		currWizPanel = p;
		currWizPanel.addWizardPanelListener(this);

/* todo:
// if this is the 1st time rendering this panel,
// then initialize it
//
if (!visitedMap.containsKey(currWizPanel)) {
    visitedMap.put(currWizPanel, null);
    currWizPanel.initialize();
}
*/
		setPanel(currWizPanel.getPanel());
		setPanelTitle(currWizPanel.getTitle());
		setHelpLocation(currWizPanel.getHelpLocation());

		HelpLocation hLoc = currWizPanel.getHelpLocation();
		HelpService help = Help.getHelpService();
		help.registerHelp(getComponent(), hLoc);
		help.registerHelp(currWizPanel.getPanel(), hLoc);

		setStatusMessage("");
		enableButtons();

		rootPanel.repaint();

		requestFocusOnDefaultComponent(currWizPanel);
	}

	private void requestFocusOnDefaultComponent(WizardPanel wizardPanel) {
		Component defaultFocusComponent = wizardPanel.getDefaultFocusComponent();

		// do this before the null check in order to clear out the last focus component
		setFocusComponent(defaultFocusComponent);

		if (defaultFocusComponent == null) {
			return; // nothing to do
		}

		// this will have no effect if we are not showing, but the above call will handle that 
		// case
		defaultFocusComponent.requestFocusInWindow();
	}

	private void setPanel(final JPanel panel) {
		if (currJPanel != panel) {
			scrollPane.setViewportView(panel);
			currJPanel = panel;

			JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
			verticalBar.setUnitIncrement(25);
			scrollPane.validate();
			updateScrollPaneBorder(panel);
		}
	}

	private void updateScrollPaneBorder(JPanel panel) {
		if (panel == null) {
			return;
		}

		scrollPane.setBackground(panel.getBackground());

		if (scrollPane.getVerticalScrollBar().isShowing()) {
			TitledBorder titledBorder =
				new TitledBorder(BorderFactory.createEmptyBorder(), "(scroll for more options)");

			Font font = titledBorder.getTitleFont();
			if (font == null) {
				// workaround for bug on Java 7
				font = titleLabel.getFont();
			}

			titledBorder.setTitleFont(font.deriveFont(10f));
			titledBorder.setTitleColor(Color.BLUE);
			titledBorder.setTitlePosition(TitledBorder.BOTTOM);
			titledBorder.setTitleJustification(TitledBorder.TRAILING);

			scrollPane.setBorder(titledBorder);
		}
		else {
			scrollPane.setBorder(BorderFactory.createEmptyBorder());
		}
	}

	private void setPanelTitle(String title) {
		titleLabel.setText(title);
	}

	private void enableButtons() {
		boolean isValid = currWizPanel.isValidInformation();
		backButton.setEnabled(panelMgr.hasPreviousPanel());
		if (isValid) {
			nextButton.setEnabled(panelMgr.hasNextPanel());
			finishButton.setEnabled(panelMgr.canFinish());
		}
		else {
			nextButton.setEnabled(false);
			finishButton.setEnabled(false);
		}

		// Update the default button that is executed when the user presses Enter.  We always
		// use the 'nextButton', unless that is disabled when the 'finishButton' is enabled
		if (nextButton.isEnabled()) {
			setDefaultButton(nextButton);
		}
		else if (finishButton.isEnabled()) {
			setDefaultButton(finishButton);
		}
	}
}
