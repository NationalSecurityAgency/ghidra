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

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import generic.theme.GThemeDefaults.Colors.Messages;
import generic.theme.Gui;
import ghidra.util.HelpLocation;
import help.Help;
import help.HelpService;
import resources.Icons;

/**
 * A dialog for displaying a series of wizard panels used to collect data from the user before
 * performing some task with the collected data. This dialog is generic and is used to display 
 * the wizard steps as defined by a {@link WizardModel}.
 * <P>
 * To use this dialog, create an instance of a {@link WizardModel} and construct this dialog
 * with that model, optionally specifying if the dialog is modal or not (default is modal). Then
 * call either the {@link #show()} or {@link #show(Component)} method to display it. If the model's 
 * purpose is to create some object, get it from the model when done.
 * <P>
 * For example, 
 * <Pre>
 * 		FooWizardModel model = new FooWizardModel();
 * 		WizardDialog wizard = new WizardDialog(model);
 * 		wizard.show();
 * 		Foo foo = model.getFoo();
 * </Pre>
 * 
 */
public class WizardDialog extends DialogComponentProvider {
	/**Default text for the 'finish' button*/
	public static final String FINISH = "Finish";
	/**Default text for the 'next' button*/
	public static final String NEXT = "Next >>";
	/**Default text for the 'back' button*/
	public static final String BACK = "<< Back";

	private final static String INIT_TITLE = "<< untitled >>";

	private static final String FONT_ID = "font.wizard.border.title";

	private WizardModel<?> model;
	private JButton backButton;
	private JButton nextButton;
	private JButton finishButton;
	private JLabel titleLabel;
	private JPanel containerPanel;

	/**
	 * Constructs a modal WizardDialog using the given model.
	 * @param model the wizard model
	 */
	public WizardDialog(WizardModel<?> model) {
		this(model, true);
	}

	/**
	 * Constructs a WizardDialog using the given model.
	 * @param modal true if the wizard should be modal
	 * @param model the wizard model
	 */
	public WizardDialog(WizardModel<?> model, boolean modal) {
		super(model.getTitle(), modal, true, true, false);
		this.model = model;
		model.initialize(this);
		addWorkPanel(buildWorkPanel());
		setRememberLocation(false);
		setRememberSize(false);
		createButtons();
		wizardStepChanged(getCurrentStep());
	}

	/**
	 * Returns the current status message being displayed in this dialog.
	 * @return the current status message being displayed in this dialog
	 */
	public String getStatusMessage() {
		return getStatusText();
	}

	/**
	 * Sets the status message on the dialog
	 * @param message the message to display in the dialog
	 */
	public void setStatusMessage(String message) {
		if (SwingUtilities.isEventDispatchThread()) {
			setStatusText(message);
		}
		else {
			Runnable r = () -> setStatusText(message);
			SwingUtilities.invokeLater(r);
		}
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
	 * Returns the current wizard panel.
	 * @return the current wizard panel
	 */
	public WizardStep<?> getCurrentStep() {
		return model.getCurrentStep();
	}

	/**
	 * Shows the wizard dialog.
	 */
	public void show() {
		show(null);
	}

	/**
	 * Shows the wizard dialog parented to the given component.
	 * @param parent the component to parent the dialog to
	 */
	public void show(Component parent) {
		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	public void dispose() {
		model.dispose();
	}

	/**
	 * Cancels the wizard
	 */
	public void cancel() {
		model.cancel();
		close();
	}

	@Override
	protected void cancelCallback() {
		cancel();
	}

	void statusChanged() {
		backButton.setEnabled(model.canGoBack());
		nextButton.setEnabled(model.canGoNext());
		setStatusText(model.getStatusMessage());
		finishButton.setEnabled(model.canFinish());
		setCancelEnabled(model.canCancel());
	}

	void wizardStepChanged(WizardStep<?> step) {
		containerPanel.removeAll();
		JComponent component = step.getComponent();
		containerPanel.add(component);
		containerPanel.repaint();

		titleLabel.setText(step.getTitle());
		HelpLocation helpLocation = step.getHelpLocation();
		setHelpLocation(helpLocation);
		HelpService help = Help.getHelpService();
		help.registerHelp(getComponent(), helpLocation);
		statusChanged();
	}

	private void createButtons() {
		backButton = new JButton(BACK);
		backButton.setMnemonic('B');
		nextButton = new JButton(NEXT);
		nextButton.setMnemonic('N');
		finishButton = new JButton(FINISH);
		finishButton.setMnemonic('F');

		backButton.addActionListener(evt -> model.goBack());
		nextButton.addActionListener(evt -> model.goNext());
		finishButton.addActionListener(evt -> model.finish());

		addButton(backButton);
		addButton(nextButton);
		addButton(finishButton);
		addCancelButton();

		setDefaultButton(nextButton);
	}

	private JPanel buildWorkPanel() {

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(createTitlePanel(), BorderLayout.NORTH);
		panel.add(createContainerPanel(), BorderLayout.CENTER);
		panel.setPreferredSize(model.getPreferredSize());
		return panel;
	}

	private Component createTitlePanel() {
		Icon wizardIcon = model.getIcon();
		titleLabel = (wizardIcon == null ? new GDLabel(INIT_TITLE)
				: new GDLabel(INIT_TITLE, wizardIcon, SwingConstants.TRAILING));

		EmptyBorderButton helpButton = new EmptyBorderButton(Icons.INFO_ICON);
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
		return titlePanel;
	}

	private JPanel createContainerPanel() {
		containerPanel = new JPanel(new BorderLayout());
		Dimension panelSize = model.getPreferredSize();
		containerPanel.setPreferredSize(panelSize);
		JComponent component = model.getCurrentStep().getComponent();
		containerPanel.add(component, BorderLayout.CENTER);
		containerPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateContainerPanelBorder();
			}
		});

		return containerPanel;
	}

	private void updateContainerPanelBorder() {
		Component component = containerPanel.getComponent(0);
		Dimension size = component.getSize();
		Dimension minSize = component.getMinimumSize();
		if (size.height < minSize.height) {
			TitledBorder titledBorder =
				new TitledBorder(BorderFactory.createEmptyBorder(), "(Dialog too small!)");
			Gui.addThemeListener(e -> {
				if (e.isFontChanged(FONT_ID)) {
					titledBorder.setTitleFont(Gui.getFont(FONT_ID));
				}
			});
			titledBorder.setTitleFont(Gui.getFont(FONT_ID));
			titledBorder.setTitleColor(Messages.NORMAL);
			titledBorder.setTitlePosition(TitledBorder.BOTTOM);
			titledBorder.setTitleJustification(TitledBorder.TRAILING);
			containerPanel.setBorder(titledBorder);
		}
		else {
			containerPanel.setBorder(BorderFactory.createEmptyBorder());
		}
	}

}
