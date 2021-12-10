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
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.Timer;

import org.apache.commons.lang3.StringUtils;
import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;

import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.event.mouse.GMouseListenerAdapter;
import docking.help.HelpService;
import docking.menu.DialogToolbarButton;
import docking.util.AnimationUtils;
import docking.widgets.label.GDHtmlLabel;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.*;
import utility.function.Callback;

/**
 * Base class used for creating dialogs in Ghidra. Subclass this to create a dialog provider that has
 * all the gui elements to appear in the dialog, then use tool.showDialog() to display your dialog.
 */
public class DialogComponentProvider
		implements ActionContextProvider, StatusListener, TaskListener {

	private static final Color WARNING_COLOR = new Color(0xff9900);

	private final static int DEFAULT_DELAY = 750;

	private static final String PROGRESS = "Progress";
	private static final String DEFAULT = "No Progress";

	private static int idCounter;

	private int id = ++idCounter;

	private boolean modal;
	private String title;

	protected JPanel rootPanel;
	private JPanel mainPanel;
	private JComponent workPanel;
	protected JPanel buttonPanel;
	private JPanel statusPanel;
	protected JButton okButton;
	protected JButton applyButton;
	protected JButton cancelButton;
	protected JButton dismissButton;
	private boolean isAlerting;
	private GDHtmlLabel statusLabel;
	private JPanel statusProgPanel; // contains status panel and progress panel
	private Timer showTimer;
	private TaskScheduler taskScheduler;
	private TaskMonitorComponent taskMonitorComponent;

	private static final KeyStroke ESC_KEYSTROKE = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);

	private CardLayout progressCardLayout;
	private JButton defaultButton;

	private DockingDialog dialog;
	private Component focusComponent;
	private JPanel toolbar;

	private final Map<DockingActionIf, DialogToolbarButton> actionMap = new HashMap<>();
	private final DialogComponentProviderPopupActionManager popupManager =
		new DialogComponentProviderPopupActionManager(this);
	private final PopupHandler popupHandler = new PopupHandler();
	private final Set<DockingActionIf> dialogActions = new HashSet<>();

	private Point initialLocation;
	private boolean resizeable = true;
	private boolean rememberLocation = true;
	private boolean rememberSize = true;
	private boolean useSharedLocation = false;
	private boolean isTransient = false;

	private Dimension defaultSize;

	/**
	 * Constructor for a GhidraDialogComponent that will be modal and will include a status line and
	 * a button panel. Its title will be the same as its name.
	 * @param title the dialog title.
	 */
	protected DialogComponentProvider(String title) {
		this(title, true, true, true, false);
	}

	/**
	 * Constructor for a GhidraDialogComponent that will include a status line and a button panel.
	 * @param title the title for this dialog.
	 * @param modal true if this dialog should be modal.
	 */
	protected DialogComponentProvider(String title, boolean modal) {
		this(title, modal, true, true, false);
	}

	/**
	 * Constructs a new GhidraDialogComponent.
	 * @param title the title for this dialog.
	 * @param modal true if this dialog should be modal.
	 * @param includeStatus true if this dialog should include a status line.
	 * @param includeButtons true if this dialog will have a button panel at
	 * the bottom.
	 * @param canRunTasks true means this dialog can execute tasks
	 *        ({@link #executeProgressTask(Task, int)} and it will show a progress monitor when
	 *        doing so.
	 */
	protected DialogComponentProvider(String title, boolean modal, boolean includeStatus,
			boolean includeButtons, boolean canRunTasks) {
		this.modal = modal;
		this.title = title;
		rootPanel = new JPanel(new BorderLayout()) {
			@Override
			public Dimension getPreferredSize() {
				Dimension minSize = getMinimumSize();
				Dimension preferredSize = super.getPreferredSize();
				preferredSize.width = Math.max(minSize.width, preferredSize.width);
				preferredSize.height = Math.max(minSize.height, preferredSize.height);
				return preferredSize;
			}
		};
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.setBorder(BorderFactory.createEtchedBorder());
		rootPanel.add(mainPanel, BorderLayout.CENTER);

		taskScheduler = new TaskScheduler(this);

		buttonPanel = new JPanel(new GridLayout(1, 0, 6, 0));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(3, 0, 0, 0));
		statusPanel = buildStatusPanel();

		if (canRunTasks) {
			progressCardLayout = new CardLayout();
			statusProgPanel = new JPanel(progressCardLayout);
			taskMonitorComponent = new TaskMonitorComponent();
			statusProgPanel.add(statusPanel, DEFAULT);
			statusProgPanel.add(taskMonitorComponent, PROGRESS);
			progressCardLayout.show(statusProgPanel, DEFAULT);
			mainPanel.add(statusProgPanel, BorderLayout.SOUTH);
		}
		else if (includeStatus) {
			mainPanel.add(statusPanel, BorderLayout.SOUTH);
		}
		if (includeButtons) {
			JPanel panel = new JPanel(new FlowLayout());
			panel.add(buttonPanel);
			rootPanel.add(panel, BorderLayout.SOUTH);
		}
		installEscapeAction();

		doInitialize();
	}

	private void installEscapeAction() {
		Action escAction = new AbstractAction("ESCAPE") {
			@Override
			public void actionPerformed(ActionEvent ev) {
				escapeCallback();
			}
		};

		KeyBindingUtils.registerAction(rootPanel, ESC_KEYSTROKE, escAction,
			JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
	}

	/** a callback mechanism for children to do work */
	protected void doInitialize() {
		// may be overridden by subclasses
	}

	public int getId() {
		return id;
	}

	public JComponent getComponent() {
		return rootPanel;
	}

	protected void repack() {
		if (dialog != null) {
			dialog.pack();
		}
	}

	protected void setDialogSize(Dimension d) {
		if (dialog != null) {
			dialog.setSize(d);
		}
	}

	protected Dimension getDialogSize() {
		if (dialog != null) {
			return dialog.getSize();
		}
		return null;
	}

	/**
	 * Sets the background on this component.
	 * @param color The color to set.
	 */
	public void setBackground(Color color) {
		rootPanel.setBackground(color);
	}

	/**
	 * Gets the background color of this component.
	 * @return The background color of this component.
	 */
	public Color getBackground() {
		return rootPanel.getBackground();
	}

	/**
	 * Sets the preferred size of the dialog.  Note that if you set the preferred size, the
	 * dialog will ignore any natural preferred size of your components.
	 * @param width the preferred width
	 * @param height the preferred height;
	 */
	public void setPreferredSize(int width, int height) {
		this.defaultSize = new Dimension(width, height);
	}

	public void setDefaultSize(int width, int height) {
		this.defaultSize = new Dimension(width, height);
	}

	public Dimension getDefaultSize() {
		return defaultSize;
	}

	public void setMinimumSize(int width, int height) {
		rootPanel.setMinimumSize(new Dimension(width, height));
	}

	/**
	 * Sets the minimum size of the dialog
	 * @param minSize the min size of the dialog
	 */
	public void setMinimumSize(Dimension minSize) {
		setMinimumSize(minSize.width, minSize.height);
	}

	/**
	 * Gets the bound of this dialog component.  This is relative the parent of this provider.
	 * @return the bound of this dialog component.
	 * @see Component#getBounds()
	 */
	protected Rectangle getBounds() {
		return rootPanel.getBounds();
	}

	/**
	 * Gets the location of this provider on the screen.  Calling {@link #getBounds()} provides
	 * a relative location.  This method provides a location absolute on the screen.
	 * @return the location of this provider on the screen.
	 * @see Component#getLocationOnScreen()
	 */
	protected Point getLocationOnScreen() {
		return rootPanel.getLocationOnScreen();
	}

	/**
	 * Returns the preferred size of this component.
	 * @return the preferred size of this component.
	 */
	public Dimension getPreferredSize() {
		return rootPanel.getPreferredSize();
	}

	/**
	 * Sets the cursor on the root panel for the dialog component.
	 * @param cursor the cursor to use.
	 */
	public void setCursor(Cursor cursor) {
		rootPanel.setCursor(cursor);
	}

	/**
	 * Used by derived classes to add dialog specific gui elements
	 * @param comp the Component containing the derived class's components.
	 */
	protected void addWorkPanel(JComponent comp) {
		workPanel = comp;
		mainPanel.add(workPanel, BorderLayout.CENTER);
		installMouseListener(workPanel);
		mainPanel.validate();
	}

	protected void removeWorkPanel() {
		if (workPanel != null) {
			mainPanel.remove(workPanel);
			uninstallMouseListener(workPanel);
			mainPanel.validate();
		}
	}

	private void installMouseListener(Component component) {
		if (component instanceof CellRendererPane) {
			return;
		}
		if (component instanceof Container) {
			Container c = (Container) component;
			c.addContainerListener(popupHandler);
			Component comps[] = c.getComponents();
			for (Component comp : comps) {
				installMouseListener(comp);
			}
		}

		if (component.isFocusable()) {
			component.addMouseListener(popupHandler);
		}
	}

	private void uninstallMouseListener(Component comp) {
		if (comp instanceof CellRendererPane) {
			return;
		}
		if (comp instanceof Container) {
			Container c = (Container) comp;
			c.removeContainerListener(popupHandler);
			Component comps[] = c.getComponents();
			for (Component comp2 : comps) {
				uninstallMouseListener(comp2);
			}
		}
		comp.removeMouseListener(popupHandler);
	}

	/**
	 * Adds a button to the button panel at the bottom of the dialog.
	 * Buttons will be added from left to right.
	 * <p>
	 * Implementation Note: Calling this method will set the given button as the default button
	 * on this dialog when:
	 * <ul>
	 * 		<li>
	 * 			No button has yet been added, and
	 * 		</li>
	 * 		<li>
	 * 			No default button has been assigned
	 * 		</li>
	 * </ul>
	 * To change this behavior, call {@link #setDefaultButton(JButton)} with the desired
	 * default button.
	 * 
	 * @param button the button
	 */
	protected void addButton(JButton button) {
		if (defaultButton == null && buttonPanel.getComponentCount() == 0) {
			// The first button we add will be a suitable default 'default button'.
			setDefaultButton(button);
		}
		buttonPanel.add(button);
	}

	/**
	 * Remove the given button from the dialog
	 * @param button the button
	 */
	protected void removeButton(JButton button) {
		buttonPanel.remove(button);
		rootPanel.validate();
	}

	/**
	 * Execute a non-modal task that has progress and can be cancelled.
	 *
	 * @param task task to execute; a progress bar is displayed next to the status field
	 *        in this dialog if the task has progress; for  indeterminate tasks, a
	 *        "spinning globe" is displayed to indicate that something is happening.
	 * @param delay number of milliseconds to delay until progress bar is displayed; a
	 *        value less than or equal to 0 means to show the progress bar immediately
	 * @throws IllegalArgumentException if the given task is modal
	 */
	protected void executeProgressTask(Task task, int delay) {
		if (taskMonitorComponent == null) {
			throw new AssertException("Cannot execute tasks in a " +
				"DialogComponentProvider that has not been created to run taks.");
		}

		if (task.isModal()) {
			throw new IllegalArgumentException("Task cannot be modal");
		}

		task.addTaskListener(this);
		taskScheduler.set(task, delay);
	}

	protected void clearScheduledTask() {
		taskScheduler.clearScheduledTask();
	}

	/**
	 * Cancel the task that is running.
	 *
	 */
	protected void cancelCurrentTask() {
		if (taskMonitorComponent != null) {
			taskMonitorComponent.cancel();
		}
	}

	/**
	 * Blocks the calling thread until the current task has completed; used
	 * by JUnit tests.
	 *
	 */
	public void waitForCurrentTask() {
		taskScheduler.waitForCurrentTask();
	}

	/**
	 * Returns true if this dialog is running a task.
	 * @return true if this dialog is running a task.
	 */
	public boolean isRunningTask() {
		return taskScheduler.isBusy();
	}

	/**
	 * Adds an "OK" button to the button panel.  The protected method
	 * okCallback() will be invoked whenever the "OK" button is pressed.
	 */
	protected void addOKButton() {
		okButton = new JButton("OK");
		okButton.setMnemonic('K');
		okButton.setName("OK");
		okButton.addActionListener(e -> okCallback());
		addButton(okButton);
	}

	/**
	 * Adds a "Cancel" button to the button panel.  The protected method
	 * CancelCallback() will be invoked whenever the "Cancel" button is pressed.
	 */
	protected void addCancelButton() {
		cancelButton = new JButton("Cancel");
		cancelButton.setMnemonic('C');
		cancelButton.setName("Cancel");
		cancelButton.addActionListener(e -> cancelCallback());
		addButton(cancelButton);
	}

	/**
	 * Adds a "Dismiss" button to the button panel.  The protected method
	 * dismissCallback() will be invoked whenever the "Dismiss" button is pressed.
	 */
	protected void addDismissButton() {
		dismissButton = new JButton("Dismiss");
		dismissButton.setMnemonic('D');
		dismissButton.setName("Dismiss");
		dismissButton.addActionListener(e -> dismissCallback());
		addButton(dismissButton);
	}

	/**
	 * Adds an "Apply" button to the button panel.  The protected method
	 * applyCallback() will be invoked whenever the "Apply" button is pressed.
	 */
	protected void addApplyButton() {
		applyButton = new JButton("Apply");
		applyButton.setMnemonic('A');
		applyButton.setName("Apply");
		applyButton.addActionListener(e -> applyCallback());
		addButton(applyButton);
	}

	/**
	 * Sets the Tooltip for the Apply button
	 * @param tooltip the tooltip
	 */
	protected void setApplyToolTip(String tooltip) {
		if (applyButton != null) {
			applyButton.setToolTipText(tooltip);
		}
	}

	protected void setOkButtonText(String text) {
		if (okButton != null) {
			okButton.setText(text);
		}
	}

	/**
	 * Sets the Tooltip for the OK button
	 * @param tooltip the tooltip
	 */
	protected void setOkToolTip(String tooltip) {
		if (okButton != null) {
			okButton.setToolTipText(tooltip);
		}
	}

	/**
	 * Sets the Tooltip for the Cancel button
	 * @param tooltip the tooltip
	 */
	protected void setCancelToolTip(String tooltip) {
		if (cancelButton != null) {
			cancelButton.setToolTipText(tooltip);
		}
	}

	protected void setCancelButtonText(String text) {
		if (cancelButton != null) {
			cancelButton.setText(text);
		}
	}

	/**
	 * Sets the Tooltip for the Dismiss button
	 * @param tooltip the tooltip
	 */
	protected void setDismissToolTip(String tooltip) {
		if (dismissButton != null) {
			dismissButton.setToolTipText(tooltip);
		}
	}

	/**
	 * Sets the enablement state of the "OK" button.
	 * @param state true to enable the button, false to disable the button.
	 */
	protected void setOkEnabled(boolean state) {
		if (okButton != null) {
			okButton.setEnabled(state);
		}
	}

	/**
	 * Sets the enablement state of the "CANCEL" button.
	 * @param state true to enable the button, false to disable the button.
	 */
	protected void setCancelEnabled(boolean state) {
		if (cancelButton != null) {
			cancelButton.setEnabled(state);
		}
	}

	/**
	 * Sets the enablement state of the "Apply" button.
	 * @param state true to enable the button, false to disable the button.
	 */
	protected void setApplyEnabled(boolean state) {
		if (applyButton != null) {
			applyButton.setEnabled(state);
		}
	}

	/**
	 * Returns true if the cancel button is enabled
	 * @return true if the cancel button is enabled
	 */
	protected boolean isCancelEnabled() {
		if (cancelButton != null) {
			return cancelButton.isEnabled();
		}
		return false;
	}

	/**
	 * Returns true if the OK button is enabled
	 * @return true if the OK button is enabled
	 */
	protected boolean isOKEnabled() {
		if (okButton != null) {
			return okButton.isEnabled();
		}
		return false;
	}

	/**
	 * Returns true if the apply button is enabled
	 * @return true if the apply button is enabled
	 */
	protected boolean isApplyEnabled() {
		if (applyButton != null) {
			return applyButton.isEnabled();
		}
		return false;
	}

	/**
	 * Sets the text in the dialog's status line using the default color
	 * 
	 * @param text the text to display in the status line
	 */
	@Override
	public void setStatusText(String text) {
		setStatusText(text, MessageType.INFO);
	}

	/**
	 * Sets the text in the dialog's status line using the specified message type to control
	 * the color.
	 *
	 * @param message the message
	 * @param type the message type
	 */
	@Override
	public void setStatusText(String message, MessageType type) {
		setStatusText(message, type, false);
	}

	@Override
	public void setStatusText(String message, MessageType type, boolean alert) {

		String text = StringUtils.isBlank(message) ? " " : message;
		Swing.runIfSwingOrRunLater(() -> doSetStatusText(text, type, alert));
	}

	private void doSetStatusText(String text, MessageType type, boolean alert) {

		SystemUtilities.assertThisIsTheSwingThread(
			"Setting text must be performed on the Swing thread");

		statusLabel.setText(text);
		statusLabel.setForeground(getStatusColor(type));
		updateStatusToolTip();

		if (alert) {
			alertMessage();
		}
	}

	/**
	 * Signals for this dialog to visually draw the user's attention to the status text
	 */
	protected void alertMessage() {
		alertMessage(Callback.dummy());
	}

	/**
	 * Signals for this dialog to visually draw the user's attention to the status text
	 * @param alertFinishedCallback this will be called when the alert is finished.  This allows
	 *        clients to perform work, like re-enabling buttons that were disabled before
	 *        calling this method
	 */
	protected void alertMessage(Callback alertFinishedCallback) {

		Swing.runIfSwingOrRunLater(() -> {
			doAlertMessage(alertFinishedCallback);
		});
	}

	private void doAlertMessage(Callback alertFinishedCallback) {

		// must be on Swing; this allows us to synchronize the 'alerting' flag
		SystemUtilities.assertThisIsTheSwingThread(
			"Alerting must be performed on the Swing thread");

		if (isAlerting) {
			return;
		}

		isAlerting = true;

		// Note: manually call validate() so the 'statusLabel' updates its bounds after
		//       the text has been setStatusText() (validation is buffered which means the
		//       normal Swing mechanism may not have yet happened).
		mainPanel.validate();
		statusLabel.setVisible(false); // disable painting in this dialog so we don't see double
		Animator animator = AnimationUtils.pulseComponent(statusLabel, 1);
		animator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				statusLabel.setVisible(true);
				alertFinishedCallback.call();
				isAlerting = false;
			}
		});
	}

	protected Color getStatusColor(MessageType type) {
		switch (type) {
			case ALERT:
				return Color.orange;
			case WARNING:
				return WARNING_COLOR;
			case ERROR:
				return Color.red;
			default:
				return Color.blue;
		}
	}

	/**
	 * Stop the timer if one was started to delay showing the progress
	 * bar.
	 *
	 */
	protected void stopProgressTimer() {
		if (showTimer != null) {
			showTimer.stop();
			showTimer = null;
		}
	}

	/**
	 * Will hide the progress panel if it was showing.
	 *
	 * @see #showTaskMonitorComponent(String, boolean, boolean)
	 */
	public void hideTaskMonitorComponent() {
		clearProgress();
	}

	protected void showProgressBar(String localTitle, boolean hasProgress, boolean canCancel,
			int delay) {
		taskMonitorComponent.reset();
		Runnable r = () -> {
			if (delay <= 0) {
				showProgressBar(localTitle, hasProgress, canCancel);
			}
			else {
				showTimer = new Timer(delay, ev -> {
					if (taskScheduler.isBusy()) {
						showProgressBar(localTitle, hasProgress, canCancel);
						showTimer = null;
					}
				});
				showTimer.setInitialDelay(delay);
				showTimer.setRepeats(false);
				showTimer.start();
			}
		};

		SystemUtilities.runSwingNow(r);
	}

	TaskMonitor showProgress(Task task, int delay) {
		showProgressBar(task.getTaskTitle(), task.hasProgress(), task.canCancel(), delay);
		return taskMonitorComponent;
	}

	private void showProgressBar(String localTitle, boolean hasProgress, boolean canCancel) {

		if (!isVisible()) {
			// It doesn't make any sense to show the task monitor when the dialog is not
			// visible, so show the dialog
			DockingWindowManager.showDialog(getParent(), this);
		}

		taskMonitorComponent.setTaskName(localTitle);
		taskMonitorComponent.showProgress(hasProgress);
		taskMonitorComponent.setCancelButtonVisibility(canCancel);
		progressCardLayout.show(statusProgPanel, PROGRESS);
		rootPanel.validate();
	}

	private void clearProgress() {
		if (taskMonitorComponent != null) {
			progressCardLayout.show(statusProgPanel, DEFAULT);
		}
	}

	/**
	 * If the status text doesn't fit in the dialog, set a tool tip
	 * for the status label so the user can see what it says.
	 * If the status message fits then there is no tool tip.
	 */
	private void updateStatusToolTip() {
		String text = statusLabel.getText();
		// Get the width of the message.
		FontMetrics fm = statusLabel.getFontMetrics(statusLabel.getFont());
		int messageWidth = 0;
		if ((fm != null) && (text != null)) {
			messageWidth = fm.stringWidth(text);
		}
		if (messageWidth > statusLabel.getWidth()) {
			statusLabel.setToolTipText(text);
		}
		else {
			statusLabel.setToolTipText(null);
		}
	}

	/**
	 * Clears the text from the dialog's status line.
	 */
	@Override
	public void clearStatusText() {
		Swing.runIfSwingOrRunLater(() -> {
			statusLabel.setText(" ");
			updateStatusToolTip();
		});
	}

	/**
	 * Returns the current status in the dialogs status line
	 * 
	 * @return the status text
	 */
	public String getStatusText() {
		return statusLabel.getText();
	}

	protected JLabel getStatusLabel() {
		return statusLabel;
	}

	/**
	 * Get the task scheduler for the dialog
	 * @return the task scheduler
	 *
	 */
	protected TaskScheduler getTaskScheduler() {
		return taskScheduler;
	}

	protected TaskMonitorComponent getTaskMonitorComponent() {
		return taskMonitorComponent;
	}

	/**
	 * Shows the progress bar for this dialog.
	 *
	 * @param localTitle the name of the task
	 * @param hasProgress true if the progress bar should show progress; false to be indeterminate
	 * @param canCancel true if the task can be cancelled
	 * @return the {@link TaskMonitor} used by to communicate progress
	 * @see #hideTaskMonitorComponent()
	 */
	public TaskMonitor showTaskMonitorComponent(String localTitle, boolean hasProgress,
			boolean canCancel) {
		showProgressBar(localTitle, hasProgress, canCancel, DEFAULT_DELAY);
		return taskMonitorComponent;
	}

	/**
	 * The callback method for when the "Apply" button is pressed.
	 */
	protected void applyCallback() {
		Msg.debug(this, "Apply button pressed");
	}

	/**
	 * The callback method for when the "OK" button is pressed.
	 */
	protected void okCallback() {
		Msg.debug(this, "Ok button pressed");
	}

	/**
	 * The callback method for when the "Cancel" button is pressed. The
	 * default behavior is to call setVisible(false) and dispose() on the
	 * dialog.
	 */
	protected void cancelCallback() {
		close();
	}

	public void close() {
		if (isShowing()) {
			dialog.close();
		}

	}

	public void dispose() {
		cancelCurrentTask();
		close();
		popupManager.dispose();

		dialogActions.forEach(DockingActionIf::dispose);

		actionMap.clear();
		dialogActions.clear();
	}

	/**
	 * The callback method for when the "Dismiss" button is pressed.
	 * The default behavior is to call the cancel Callback.
	 */
	protected void dismissCallback() {
		cancelCallback();
	}

	/**
	 * The callback method for when the escape key is pressed.  The default
	 * behavior is the call setVisible(false) on the dialog.
	 */
	protected void escapeCallback() {
		dismissCallback();
	}

	private JPanel buildStatusPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		statusLabel = new GDHtmlLabel(" ");
		statusLabel.setName("statusLabel");
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
		statusLabel.setForeground(Color.blue);
		statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));
		statusLabel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateStatusToolTip();
			}
		});

		// use a strut panel so the size of the message area does not change if we make
		// the message label not visible
		int height = statusLabel.getPreferredSize().height;

		panel.add(Box.createVerticalStrut(height), BorderLayout.WEST);
		panel.add(statusLabel, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Returns true if this component should be displayed in a modal dialog
	 * @return true if this component should be displayed in a modal dialog
	 */
	public boolean isModal() {
		return modal;
	}

	/**
	 * Sets the horizontal position of the status label.
	 * @param justification  One of the following constants
	 *           defined in <code>SwingConstants</code>:
	 *           <code>LEFT</code>,
	 *           <code>CENTER</code> (the default for image-only labels),
	 *           <code>RIGHT</code>,
	 */
	public void setStatusJustification(int justification) {
		statusLabel.setHorizontalAlignment(justification);
	}

	/**
	 * Notification that the task was canceled; the progress panel is
	 * removed.
	 * @param task task that was canceled
	 */
	@Override
	public void taskCancelled(Task task) {
		clearProgress();
		setStatusText("operation canceled");
		taskScheduler.clearScheduledTask();
	}

	/**
	 * Notification that the given task completed so that the progress
	 * panel can be removed.
	 * @param task task that completed
	 */
	@Override
	public void taskCompleted(Task task) {
		clearProgress();
	}

	/**
	 * Sets the component that should be given focus when the dialog is activated.
	 * <p>
	 * Implementation Note:  If the given component is a JButton, then that component will be
	 * made the default button.
	 *
	 * @param focusComponent the component that should receive default focus.
	 * @see #setFocusComponent(Component)
	 */
	public void setFocusComponent(Component focusComponent) {
		this.focusComponent = focusComponent;

		if (focusComponent instanceof JButton && defaultButton == null) {
			setDefaultButton((JButton) focusComponent);
		}
	}

	/**
	 * Returns the component that will receive focus when the dialog is shown
	 * @return the component
	 */
	public Component getFocusComponent() {
		return focusComponent;
	}

	/**
	 * Set the help Location for this dialog.
	 * @param helpLocation the helpLocation for this dialog.
	 */
	public void setHelpLocation(HelpLocation helpLocation) {
		DockingWindowManager.setHelpLocation(rootPanel, helpLocation);
	}

	/**
	 * Returns the help location for this dialog
	 * @return the help location
	 */
	public HelpLocation getHelpLocatdion() {
		HelpService helpService = DockingWindowManager.getHelpService();
		return helpService.getHelpLocation(rootPanel);
	}

	/**
	 * Sets the button to make "Default" when the dialog is shown.  If no default button is
	 * desired, then pass <code>null</code> as the <code>button</code> value.
	 * @param button the button to make default enabled.
	 */
	public void setDefaultButton(JButton button) {
		defaultButton = button;

		if (isShowing()) {
			// update the button while we are showing
			dialog.getRootPane().setDefaultButton(button);
		}
	}

	/**
	 * Returns the default button for the dialog.
	 * @return the button
	 */
	public JButton getDefaultButton() {
		return defaultButton;
	}

	/**
	 * Sets the title to be displayed in the dialogs title bar
	 * @param title the title
	 */
	public void setTitle(String title) {
		this.title = title;
		if (dialog != null) {
			dialog.setTitle(title);
		}
	}

	protected Component getGlassPane() {
		return dialog.getRootPane().getGlassPane();
	}

	protected void setGlassPane(Component component) {
		if (dialog == null) {
			throw new IllegalStateException(
				"Attempted to set the glass pane before the dialog is shown");
		}
		dialog.getRootPane().setGlassPane(component);
		dialog.validate();
	}

	/**
	 * Returns the title for this component
	 * @return the title
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * Moves the dialog associated with this provider to the front.
	 */
	public void toFront() {
		if (dialog != null) {
			dialog.toFront();
		}
	}

	void setDialog(DockingDialog dialog) {
		this.dialog = dialog;
	}

	DockingDialog getDialog() {
		return dialog;
	}

	protected Component getParent() {
		if (dialog == null) {
			return null;
		}
		return dialog.getParent();
	}

	public boolean isVisible() {
		return ((dialog != null) && dialog.isVisible());
	}

	public boolean isShowing() {
		return ((dialog != null) && dialog.isShowing());
	}

	/**
	 * Override this method if you want to do something when the dialog is made visible
	 */
	protected void dialogShown() {
		// may be overridden by subclasses
	}

	/**
	 * Override this method if you want to do something when the dialog is made invisible
	 */
	protected void dialogClosed() {
		// may be overridden by subclasses
	}

	/**
	 * Sets the initial location for the dialog
	 * @param x the x coordinate
	 * @param y the y coordinate
	 */
	public void setInitialLocation(int x, int y) {
		initialLocation = new Point(x, y);
	}

	/**
	 * Returns the initial location for the dialog or null if none was set
	 * @return the point
	 */
	public Point getIntialLocation() {
		return initialLocation;
	}

	/**
	 * Sets the resizable property for the corresponding dialog.
	 * @param resizeable if false the user will not be able to resize the dialog.
	 */
	public void setResizable(boolean resizeable) {
		this.resizeable = resizeable;
	}

	public boolean isResizeable() {
		return resizeable;
	}

	/**
	 * An optional extension point for subclasses to provider action context for the actions used by
	 * this provider.
	 *
	 * @param event The mouse event used (may be null) to generate a popup menu
	 */
	@Override
	public ActionContext getActionContext(MouseEvent event) {

		Component c = getComponent();
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusedComponent = kfm.getFocusOwner();
		if (focusedComponent != null && SwingUtilities.isDescendingFrom(focusedComponent, c)) {
			c = focusedComponent;
		}

		if (event == null) {
			return new ActionContext(null, c);
		}

		Component sourceComponent = event.getComponent();
		if (sourceComponent != null) {
			c = sourceComponent;
		}
		return new ActionContext(null, c).setSourceObject(event.getSource());
	}

	/**
	 * Signals to this provider that it needs to updated the enabled state of its managed
	 * actions.
	 */
	protected void notifyContextChanged() {
		ActionContext context = getActionContext(null);
		if (context == null) {
			context = new ActionContext();
		}
		Set<DockingActionIf> keySet = actionMap.keySet();
		for (DockingActionIf action : keySet) {
			action.setEnabled(action.isEnabledForContext(context));
		}
	}

	public Set<DockingActionIf> getActions() {
		return new HashSet<>(dialogActions);
	}

	private void addToolbarAction(final DockingActionIf action) {
		if (action.getToolBarData() == null) {
			return;
		}

		if (toolbar == null) {
			toolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
			toolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
			mainPanel.add(toolbar, BorderLayout.NORTH);
		}

		DialogToolbarButton button = new DialogToolbarButton(action, this);
		toolbar.add(button);
		actionMap.put(action, button);
	}

	/**
	 * Add an action to this dialog.  Only actions with icons are added to the toolbar.
	 * Note, if you add an action to this dialog, do not also add the action to
	 * the tool, as this dialog will do that for you.
	 * @param action the action
	 */
	public void addAction(final DockingActionIf action) {
		dialogActions.add(action);
		addToolbarAction(action);
		popupManager.addAction(action);
		addKeyBindingAction(action);
	}

	private void addKeyBindingAction(DockingActionIf action) {

		// add the action to the tool in order get key event management (key bindings
		// options and key event processing)
		DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
		if (dwm == null) {
			// This implies the client dialog has been shown outside of the plugin framework. In
			// that case, the client will not get key event processing for dialog actions.
			return;
		}

		Tool tool = dwm.getTool();
		tool.addAction(new DialogActionProxy(action));
	}

	public void removeAction(DockingActionIf action) {
		dialogActions.remove(action);
		JButton button = actionMap.remove(action);
		if (button != null && toolbar != null) {
			toolbar.remove(button);
		}
	}

	/**
	 * Sets this dialog to remember its location from one invocation to the next. The default is to
	 * remember location.
	 * @param rememberLocation true to remember, false otherwise.
	 */
	public void setRememberLocation(boolean rememberLocation) {
		this.rememberLocation = rememberLocation;
	}

	/**
	 * Returns true if this dialog remembers its location from one invocation to the next.
	 * @return true if this dialog remembers its location from one invocation to the next.
	 */
	public boolean getRememberLocation() {
		return rememberLocation;
	}

	/**
	 * Sets this dialog to remember its size from one invocation to the next. The default is to
	 * remember size.
	 * @param rememberSize true to remember, false otherwise.
	 */
	public void setRememberSize(boolean rememberSize) {
		this.rememberSize = rememberSize;
	}

	/**
	 * Returns true if this dialog remembers its size from one invocation to the next.
	 * @return true if this dialog remembers its size from one invocation to the next.
	 */
	public boolean getRemberSize() {
		return rememberSize;
	}

	/**
	 * Returns true if this dialog uses shared location and size information.
	 * @return true if this dialog uses shared location and size information.
	 * @see #setUseSharedLocation(boolean)
	 */
	public boolean getUseSharedLocation() {
		return useSharedLocation;
	}

	/**
	 * Specifies whether or not this dialog component should use the same remembered location (and
	 * size) no matter which window this dialog is launched from.  The default is not to use
	 * shared location and size, which means that there is a remembered location and size for this
	 * dialog for each window that has launched it (i.e. the window is the parent of the dialog).
	 * 
	 * @param useSharedLocation true to share locations
	 */
	public void setUseSharedLocation(boolean useSharedLocation) {
		this.useSharedLocation = useSharedLocation;
	}

	/**
	 * Returns true if this dialog is intended to be shown and hidden relatively quickly.  This
	 * is used to determine if this dialog should be allowed to parent other components.   The
	 * default is false.
	 * 
	 * @return true if this dialog is transient
	 */
	public boolean isTransient() {
		return isTransient;
	}

	/**
	 * Sets this dialog to be transient (see {@link #isTransient()}
	 * 
	 * @param isTransient true for transient; false is the default
	 */
	public void setTransient(boolean isTransient) {
		this.isTransient = isTransient;
	}

	@Override
	public String toString() {
		return getTitle();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class PopupHandler extends GMouseListenerAdapter implements ContainerListener {

		@Override
		public void popupTriggered(MouseEvent e) {
			ActionContext actionContext = getActionContext(e);
			popupManager.popupMenu(actionContext, e);
		}

		@Override
		public void componentAdded(ContainerEvent e) {
			installMouseListener(e.getChild());
		}

		@Override
		public void componentRemoved(ContainerEvent e) {
			uninstallMouseListener(e.getChild());
		}

	}

	/**
	 * A placeholder action that we register with the tool in order to get key event management
	 */
	private class DialogActionProxy extends DockingActionProxy {

		public DialogActionProxy(DockingActionIf dockingAction) {
			super(dockingAction);
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return false;
		}

		@Override
		public ToolBarData getToolBarData() {
			return null;
		}
	}
}
