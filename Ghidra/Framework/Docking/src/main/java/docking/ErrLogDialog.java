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
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.swing.*;

import docking.widgets.ScrollableTextArea;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GIconLabel;
import generic.util.WindowUtilities;
import ghidra.framework.Application;
import ghidra.util.HTMLUtilities;

public class ErrLogDialog extends DialogComponentProvider {
	private static final int TEXT_ROWS = 30;
	private static final int TEXT_COLUMNS = 80;
	private static final int ERROR_BUFFER_SIZE = 1024;

	private static final String SEND = "Log Error...";
	private static final String DETAIL = "Details >>>";
	private static final String CLOSE = "<<< Close";

	private static final String EOL = "\n";
	private static final String SEPARATOR_LINE =
		"---------------------------------------------------";

	/** tracks 'details panel' open state across invocations */
	private static boolean isShowingDetails = false;

	// state-dependent gui members
	private ErrorDetailsPanel detailsPanel;
	private JButton detailsButton;
	private JButton sendButton;
	private JPanel mainPanel;
	private static ErrorReporter errorReporter;

	public static ErrLogDialog createExceptionDialog(String title, String message, String details) {
		return new ErrLogDialog(title, message, details, true);
	}

	public static ErrLogDialog createLogMessageDialog(String title, String message,
			String details) {
		return new ErrLogDialog(title, message, details, false);
	}

	/**
	 * Constructor.
	 * Used by the Err class's static methods for logging various
	 * kinds of errors: Runtime, System, User, Asserts
	 */
	private ErrLogDialog(String title, String message, String details, boolean isException) {
		super(title != null ? title : "Error", true, false, true, false);
		setRememberSize(false);
		setRememberLocation(false);
		buildMainPanel(message, addUsefulReportingInfo(details), isException);
	}

	private String addUsefulReportingInfo(String details) {
		StringBuilder sb = new StringBuilder(details);
		sb.append(EOL);
		sb.append(SEPARATOR_LINE);
		sb.append(EOL);
		sb.append("Build Date: ");
		sb.append(Application.getBuildDate());
		sb.append(EOL);
		sb.append(Application.getName());
		sb.append(" Version: ");
		sb.append(Application.getApplicationVersion());
		sb.append(EOL);
		sb.append("Java Home: ");
		sb.append(System.getProperty("java.home"));
		sb.append(EOL);
		sb.append("JVM Version: ");
		sb.append(System.getProperty("java.vendor"));
		sb.append(" ");
		sb.append(System.getProperty("java.version"));
		sb.append(EOL);
		sb.append("OS: ");
		sb.append(System.getProperty("os.name"));
		sb.append(" ");
		sb.append(System.getProperty("os.version"));
		sb.append(" ");
		sb.append(System.getProperty("os.arch"));
		sb.append(EOL);
		sb.append("Workstation: ");
		sb.append(getHostname());
		sb.append(EOL);
		return sb.toString();
	}

	private Object getHostname() {
		String hostname = "<unknown>";
		try {
			InetAddress addr = InetAddress.getLocalHost();
			hostname = addr.getCanonicalHostName();
		}
		catch (UnknownHostException e) {
			// ignore
		}
		return hostname;
	}

	public static void setErrorReporter(ErrorReporter errorReporter) {
		ErrLogDialog.errorReporter = errorReporter;
	}

	public static ErrorReporter getErrorReporter() {
		return errorReporter;
	}

	private void buildMainPanel(String message, String details, boolean isException) {

		JPanel introPanel = new JPanel(new BorderLayout(10, 10));
		introPanel.add(
			new GIconLabel(UIManager.getIcon("OptionPane.errorIcon"), SwingConstants.RIGHT),
			BorderLayout.WEST);
		introPanel.add(new GHtmlLabel(HTMLUtilities.toHTML(message)), BorderLayout.CENTER);

		mainPanel = new JPanel(new BorderLayout(10, 20));
		mainPanel.add(introPanel, BorderLayout.NORTH);

		sendButton = new JButton(SEND);
		sendButton.addActionListener(e -> sendDetails());

		detailsPanel = new ErrorDetailsPanel();
		detailsButton = new JButton(isShowingDetails ? CLOSE : DETAIL);
		detailsButton.addActionListener(e -> {
			String label = detailsButton.getText();
			showDetails(label.equals(DETAIL));
		});

		if (isException) {
			detailsPanel.setExceptionMessage(details);
		}
		else {
			detailsPanel.setLogMessage(details);
		}

		JPanel buttonPanel = new JPanel(new GridLayout(2, 1, 5, 5));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		if (errorReporter != null) {
			buttonPanel.add(sendButton);
		}
		buttonPanel.add(detailsButton);

		introPanel.add(buttonPanel, BorderLayout.EAST);
		mainPanel.add(detailsPanel, BorderLayout.CENTER);

		addWorkPanel(mainPanel);

		addOKButton();

		// show the details panel if it was showing previously
		detailsPanel.setVisible(isShowingDetails);

//        setHelpLocation(new HelpLocation(HelpTopics.INTRO, "Err"));
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		cancelCallback();
	}

	/**
	 * Send error details from dialog.
	 */
	private void sendDetails() {
		String details = detailsPanel.getDetails();
		String title = getTitle();
		close();
		errorReporter.report(rootPanel, title, details);
	}

	/**
	 * opens and closes the details panel; used also by Err when
	 * showLog is called from SessionGui Help menu to show details
	 * when visible
	 */
	private void showDetails(boolean visible) {
		isShowingDetails = visible;
		String label = (visible ? CLOSE : DETAIL);
		detailsButton.setText(label);
		detailsPanel.setVisible(visible);
		repack();  // need to re-pack so the detailsPanel can be hidden correctly
	}

	// custom "pack" so the detailsPanel can be shown/hidden correctly
	@Override
	protected void repack() {

		// hide the dialog so that the user doesn't see us resize and then move it, which looks
		// awkward 
		getDialog().setVisible(false);

		detailsPanel.invalidate(); // force to be invalid so resizes correctly
		rootPanel.validate();

		super.repack();

		// center the dialog after its size changes for a cleaner appearance
		DockingDialog dialog = getDialog();
		Container parent = dialog.getParent();
		Point centerPoint = WindowUtilities.centerOnComponent(parent, dialog);
		dialog.setLocation(centerPoint);

		getDialog().setVisible(true);
	}

	@Override
	protected void dialogShown() {

		// TODO test that the parent DockingDialog code handles this....
		WindowUtilities.ensureOnScreen(getDialog());
	}

	/**
	 * scrolled text panel used to display the error message details;
	 * each time an error message is "added", appends the contents to
	 * the internal StringBuffer.
	 */
	private class ErrorDetailsPanel extends JPanel {
		private ScrollableTextArea textDetails;
		private StringBuffer errorDetailsBuffer;
		private Dimension closedSize;
		private Dimension openedSize;

		private ErrorDetailsPanel() {
			super(new BorderLayout(0, 0));
			errorDetailsBuffer = new StringBuffer(ERROR_BUFFER_SIZE);
			textDetails = new ScrollableTextArea(TEXT_ROWS, TEXT_COLUMNS);
			textDetails.setEditable(false);
			add(textDetails, BorderLayout.CENTER);
			validate();
			textDetails.scrollToBottom();

			// set the initial preferred size of this panel
			// when "closed"
			Rectangle bounds = getBounds();
			closedSize = new Dimension(bounds.width, 0);

			addComponentListener(new ComponentAdapter() {
				@Override
				public void componentResized(ComponentEvent event) {
					if (!isShowing()) {
						return;
					}
					Rectangle localBounds = getBounds();
					if (detailsButton.getText().equals(DETAIL)) {
						closedSize.width = localBounds.width;
					}
					else {
						openedSize = new Dimension(localBounds.width, localBounds.height);
					}
				}
			});
		}

		@Override
		public Dimension getPreferredSize() {
			if (detailsButton.getText().equals(DETAIL)) {
				return closedSize;
			}

			if (openedSize == null) {
				return super.getPreferredSize();
			}

			return openedSize;
		}

		/**
		 * resets the current error buffer to the contents of msg
		 */
		private void setLogMessage(String msg) {
			errorDetailsBuffer = new StringBuffer(msg);
			textDetails.setText(msg);

			// scroll to bottom so user is viewing the last message
			textDetails.scrollToBottom();
		}

		private void setExceptionMessage(String msg) {
			errorDetailsBuffer = new StringBuffer(msg);
			textDetails.setText(msg);

			// scroll to the top the see the pertinent part of the exception
			textDetails.scrollToTop();
		}

		private final String getDetails() {
			return errorDetailsBuffer.toString();
		}
	}

}
