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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.*;

import docking.widgets.ScrollableTextArea;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GIconLabel;
import docking.widgets.table.*;
import generic.json.Json;
import generic.util.WindowUtilities;
import ghidra.docking.settings.Settings;
import ghidra.framework.Application;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.HTMLUtilities;
import ghidra.util.Swing;
import ghidra.util.table.column.DefaultTimestampRenderer;
import ghidra.util.table.column.GColumnRenderer;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A dialog that takes error text and displays it with an option details button.  If there is
 * an {@link ErrorReporter}, then a button is provided to report the error.
 */
public class ErrLogDialog extends AbstractErrDialog {
	private static final int TEXT_ROWS = 20;
	private static final int TEXT_COLUMNS = 80;

	private static final String SEND = "Log Error...";
	private static final String DETAIL = "Details >>>";
	private static final String CLOSE = "<<< Close";

	private static final String EOL = "\n";
	private static final String SEPARATOR_LINE =
		"---------------------------------------------------";

	/** tracks 'details panel' open state across invocations */
	private static boolean isShowingDetails = false;

	private int errorId = 0;

	// state-dependent gui members
	private ErrorDetailsSplitPane detailsPane;
	private JButton detailsButton;
	private JButton sendButton;
	private JPanel mainPanel;
	private static ErrorReporter errorReporter;

	private List<ErrorEntry> errors = new ArrayList<>();
	private String baseTitle;

	public static ErrLogDialog createExceptionDialog(String title, String message, Throwable t) {
		return new ErrLogDialog(title, message, t);
	}

	private ErrLogDialog(String title, String message, Throwable throwable) {
		super(title != null ? title : "Error");

		baseTitle = getTitle();

		ErrorEntry error = new ErrorEntry(message, throwable);
		errors.add(error);

		setRememberSize(false);
		setRememberLocation(false);
		buildMainPanel(message);
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

	private void buildMainPanel(String message) {

		JPanel introPanel = new JPanel(new BorderLayout(10, 10));
		introPanel.add(
			new GIconLabel(UIManager.getIcon("OptionPane.errorIcon"), SwingConstants.RIGHT),
			BorderLayout.WEST);
		String html = HTMLUtilities.toHTML(message);
		introPanel.add(new GHtmlLabel(html) {
			@Override
			public Dimension getPreferredSize() {
				// rendering HTML the label can expand larger than the screen; keep it reasonable
				Dimension size = super.getPreferredSize();
				size.width = 300;
				return size;
			}
		}, BorderLayout.CENTER);

		mainPanel = new JPanel(new BorderLayout(10, 20));
		mainPanel.add(introPanel, BorderLayout.NORTH);

		sendButton = new JButton(SEND);
		sendButton.addActionListener(e -> sendDetails());

		detailsButton = new JButton(isShowingDetails ? CLOSE : DETAIL);
		detailsButton.addActionListener(e -> {
			String label = detailsButton.getText();
			showDetails(label.equals(DETAIL));
		});

		detailsPane = new ErrorDetailsSplitPane();

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 5, 5));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		if (errorReporter != null) {
			buttonPanel.add(sendButton);
		}
		buttonPanel.add(detailsButton);

		introPanel.add(buttonPanel, BorderLayout.EAST);
		mainPanel.add(detailsPane, BorderLayout.CENTER);

		addWorkPanel(mainPanel);

		addOKButton();
		setDefaultButton(okButton);

		// show the details panel if it was showing previously
		detailsPane.setVisible(isShowingDetails);
		detailsPane.selectFirstError();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		cancelCallback();
	}

	private void sendDetails() {
		String details = detailsPane.getDetails();
		String title = getTitle();
		close();
		errorReporter.report(rootPanel, title, details);
	}

	private void showDetails(boolean visible) {
		isShowingDetails = visible;
		String label = (visible ? CLOSE : DETAIL);
		detailsButton.setText(label);
		detailsPane.setVisible(visible);
		repack();  // need to re-pack so the detailsPanel can be hidden correctly
	}

	@Override
	public String getMessage() {
		return detailsPane.getMessage();
	}

	@Override
	protected void dialogShown() {
		WindowUtilities.ensureOnScreen(getDialog());
		Swing.runLater(() -> okButton.requestFocusInWindow());
	}

	@Override
	void addException(String message, Throwable t) {

		int n = errors.size();
		if (n > MAX_EXCEPTIONS) {
			return;
		}

		errors.add(new ErrorEntry(message, t));

		detailsPane.update();

		updateTitle(); // signal the new error
	}

	@Override
	int getExceptionCount() {
		return errors.size();
	}

	@Override
	String getBaseTitle() {
		return baseTitle;
	}

	private class ErrorDetailsSplitPane extends JSplitPane {

		private final double TOP_PREFERRED_RESIZE_WEIGHT = .80;
		private ErrorDetailsPanel detailsPanel;
		private ErrorDetailsTablePanel tablePanel;

		private Dimension openedSize;

		ErrorDetailsSplitPane() {
			super(VERTICAL_SPLIT);
			setResizeWeight(TOP_PREFERRED_RESIZE_WEIGHT);

			detailsPanel = new ErrorDetailsPanel();
			tablePanel = new ErrorDetailsTablePanel();

			setTopComponent(detailsPanel);
			setBottomComponent(tablePanel);

			addComponentListener(new ComponentAdapter() {
				@Override
				public void componentResized(ComponentEvent event) {
					if (!isShowing()) {
						return;
					}
					Rectangle localBounds = getBounds();
					if (!detailsButton.getText().equals(DETAIL)) {
						openedSize = new Dimension(localBounds.width, localBounds.height);
					}
				}
			});
		}

		void selectFirstError() {
			tablePanel.selectFirstError();
		}

		String getDetails() {
			return detailsPanel.getDetails();
		}

		String getMessage() {
			return detailsPanel.getMessage();
		}

		void setError(ErrorEntry err) {
			detailsPanel.setError(err);
		}

		void update() {
			tablePanel.update();
		}

		@Override
		public Dimension getPreferredSize() {
			Dimension superSize = super.getPreferredSize();
			if (detailsButton.getText().equals(DETAIL)) {
				return superSize;
			}

			if (openedSize == null) {
				return superSize;
			}

			return openedSize;
		}
	}

	private class ErrorDetailsTablePanel extends JPanel {

		private ErrEntryTableModel model;
		private GTable errorsTable;
		private GTableFilterPanel<ErrorEntry> tableFilterPanel;

		ErrorDetailsTablePanel() {
			setLayout(new BorderLayout());
			model = new ErrEntryTableModel();
			errorsTable = new GTable(model);
			tableFilterPanel = new GTableFilterPanel<>(errorsTable, model);

			errorsTable.getSelectionManager().addListSelectionListener(e -> {
				if (e.getValueIsAdjusting()) {
					return;
				}

				int firstIndex = errorsTable.getSelectedRow();
				if (firstIndex == -1) {
					return;
				}
				ErrorEntry err = tableFilterPanel.getRowObject(firstIndex);
				detailsPane.setError(err);
			});

			JPanel tablePanel = new JPanel(new BorderLayout());
			tablePanel.add(new JScrollPane(errorsTable), BorderLayout.CENTER);
			tablePanel.add(tableFilterPanel, BorderLayout.SOUTH);

			add(tablePanel, BorderLayout.CENTER);

			// initialize this value to something small so the full dialog will not consume the
			// entire screen height
			setPreferredSize(new Dimension(400, 100));
		}

		void selectFirstError() {
			errorsTable.selectRow(0);
		}

		void update() {
			model.fireTableDataChanged();
		}
	}

	/**
	 * scrolled text panel used to display the error message details;
	 * each time an error message is "added", appends the contents to
	 * the internal StringBuffer.
	 */
	private class ErrorDetailsPanel extends JPanel {

		private ScrollableTextArea textDetails;
		private ErrorEntry error;

		private ErrorDetailsPanel() {
			super(new BorderLayout(0, 0));
			textDetails = new ScrollableTextArea(TEXT_ROWS, TEXT_COLUMNS);
			textDetails.setEditable(false);

			add(textDetails, BorderLayout.CENTER);

			validate();
			textDetails.scrollToBottom();
		}

		@Override
		public Dimension getPreferredSize() {
			Dimension size = super.getPreferredSize();

			// Cap preferred width to something reasonable; most displays have more than 1000 width.
			// Users can still resize as desired
			size.width = Math.min(size.width, 1000);
			return size;
		}

		void setError(ErrorEntry e) {
			error = e;
			setExceptionMessage(e.getDetailsText());
		}

		private void setExceptionMessage(String message) {

			String updated = addUsefulReportingInfo(message);
			textDetails.setText(updated);

			// scroll to the top the see the pertinent part of the exception
			textDetails.scrollToTop();
		}

		String getDetails() {
			return textDetails.getText();
		}

		String getMessage() {
			return error.getMessage();
		}
	}

	private class ErrorEntry {

		private String message;
		private String details;
		private Date timestamp = new Date();
		private int myId = ++errorId;

		ErrorEntry(String message, Throwable t) {
			String updated = message;
			if (HTMLUtilities.isHTML(updated)) {
				updated = HTMLUtilities.fromHTML(updated);
			}
			this.message = updated;

			if (t != null) {
				this.details = ReflectionUtilities.stackTraceToString(t);
			}
		}

		int getId() {
			return myId;
		}

		String getMessage() {
			return message;
		}

		Date getTimestamp() {
			return timestamp;
		}

		String getDetailsText() {
			if (details == null) {
				return message;
			}
			return details;
		}

		String getDetails() {
			return details;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}

	private class ErrEntryTableModel extends GDynamicColumnTableModel<ErrorEntry, Object> {

		public ErrEntryTableModel() {
			super(new ServiceProviderStub());
		}

		@Override
		protected TableColumnDescriptor<ErrorEntry> createTableColumnDescriptor() {
			TableColumnDescriptor<ErrorEntry> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new IdColumn(), 1, true);
			descriptor.addVisibleColumn(new MessageColumn());
			descriptor.addHiddenColumn(new DetailsColumn());
			descriptor.addVisibleColumn(new TimestampColumn());
			return descriptor;
		}

		@Override
		public String getName() {
			return "Unexpectd Errors";
		}

		@Override
		public List<ErrorEntry> getModelData() {
			return errors;
		}

		@Override
		public Object getDataSource() {
			return null;
		}

		private class IdColumn extends AbstractDynamicTableColumnStub<ErrorEntry, Integer> {

			@Override
			public Integer getValue(ErrorEntry rowObject, Settings settings, ServiceProvider sp)
					throws IllegalArgumentException {
				return rowObject.getId();
			}

			@Override
			public String getColumnName() {
				return "#";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 40;
			}
		}

		private class MessageColumn extends AbstractDynamicTableColumnStub<ErrorEntry, String> {

			@Override
			public String getValue(ErrorEntry rowObject, Settings settings, ServiceProvider sp)
					throws IllegalArgumentException {
				return rowObject.getMessage();
			}

			@Override
			public String getColumnName() {
				return "Message";
			}

		}

		private class DetailsColumn extends AbstractDynamicTableColumnStub<ErrorEntry, String> {

			@Override
			public String getValue(ErrorEntry rowObject, Settings settings, ServiceProvider sp)
					throws IllegalArgumentException {
				return rowObject.getDetails();
			}

			@Override
			public String getColumnName() {
				return "Details";
			}
		}

		private class TimestampColumn extends AbstractDynamicTableColumnStub<ErrorEntry, Date> {

			private GColumnRenderer<Date> renderer = new DefaultTimestampRenderer();

			@Override
			public Date getValue(ErrorEntry rowObject, Settings settings, ServiceProvider sp)
					throws IllegalArgumentException {
				return rowObject.getTimestamp();
			}

			@Override
			public String getColumnName() {
				return "Time";
			}

			@Override
			public GColumnRenderer<Date> getColumnRenderer() {
				return renderer;
			}
		}
	}
}
