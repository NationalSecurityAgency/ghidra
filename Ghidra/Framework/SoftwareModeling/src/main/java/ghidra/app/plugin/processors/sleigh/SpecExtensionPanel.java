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
package ghidra.app.plugin.processors.sleigh;

import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.*;

import org.xml.sax.SAXException;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.*;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.SpecExtension;
import ghidra.program.database.SpecExtension.DocInfo;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;
import ghidra.xml.XmlParseException;

public class SpecExtensionPanel extends JPanel {
	private ProgramDB program;
	private PropertyChangeListener listener;
	private boolean unappliedChanges;
	private SpecExtension specExtension;
	private List<CompilerElement> tableElements;
	private ExtensionTableModel tableModel;
	private GTable extensionTable;
	private JButton exportButton;
	private JButton removeButton;
	private ListSelectionModel selectionModel;

	private final static int EXTENSION_TYPE_COLUMN = 0;
	private final static int NAME_COLUMN = 1;
	private final static int STATUS_COLUMN = 2;

	/**
	 *  Status of a particular compiler specification element
	 */
	public enum Status {
		// The order is used to sort the table
		CORE("core"),					// A core element (cannot be deleted)
		EXTENSION("extension"),			// An extension thats already present (and won't be changed)
		EXTENSION_ERROR("extension(parse error)"),	// An extension (already present) that didn't parse
		EXTENSION_INSTALL("install"),	// A pending extension to be installed
		EXTENSION_REPLACE("replace"),	// A pending extension replacing existing
		EXTENSION_REMOVE("remove"),		// An extension to be removed
		EXTENSION_OVERRIDE("override"),	// An extension overriding a core module
		EXTENSION_OVERPENDING("override pending");	// A pending extension which overrides

		private String formalName;

		private Status(String nm) {
			formalName = nm;
		}
	}

	private static final String LAST_EXPORT_DIRECTORY = "LastSpecificationExportDirectory";
	public static final String PREFERENCES_FILE_EXTENSION = ".xml";
	private static final GhidraFileFilter FILE_FILTER = new GhidraFileFilter() {
		@Override
		public boolean accept(File pathname, GhidraFileChooserModel model) {
			return (pathname.isDirectory()) ||
				(pathname.getName().endsWith(PREFERENCES_FILE_EXTENSION));
		}

		@Override
		public String getDescription() {
			return "Specification XML Files";
		}
	};

	/**
	 * A row in the table of compiler spec elements
	 */
	private static class CompilerElement implements Comparable<CompilerElement> {

		String name;
		String optionName;
		SpecExtension.Type type;
		Status status;
		String xmlString;

		public CompilerElement(String nm, SpecExtension.Type tp, Status st) {
			name = nm;
			type = tp;
			optionName = type.getOptionName(name);
			status = st;
			xmlString = null;
		}

		/**
		 * Return true if the element is already installed (not pending)
		 * @return true for an existing extension
		 */
		public boolean isExisting() {
			return (status == Status.CORE || status == Status.EXTENSION ||
				status == Status.EXTENSION_ERROR || status == Status.EXTENSION_OVERRIDE);
		}

		@Override
		public int compareTo(CompilerElement o) {
			if (type != o.type) {
				return type.ordinal() - o.type.ordinal();
			}
			if (status != o.status) {
				return status.ordinal() - o.status.ordinal();
			}
			return name.compareTo(o.name);
		}
	}

	/**
	 * Selection listener class for the table model.
	 */
	private class TableSelectionListener implements ListSelectionListener {
		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (e.getValueIsAdjusting()) {
				return;
			}

			CompilerElement compilerElement = getSelectedCompilerElement();
			if (compilerElement == null) {
				removeButton.setEnabled(false);
				exportButton.setEnabled(false);
				return;
			}
			boolean rowExisting = compilerElement.isExisting();
			removeButton.setEnabled(rowExisting && compilerElement.status != Status.CORE);
			exportButton.setEnabled(rowExisting);
		}
	}

	private class ExtensionTableModel extends AbstractGTableModel<CompilerElement> {
		private final String[] columnNames = { "Extension Type", "Name", "Status" };

		@Override
		public String getColumnName(int column) {
			return columnNames[column];
		}

		@Override
		public int getColumnCount() {
			return columnNames.length;
		}

		@Override
		public String getName() {
			return "Compiler Specification Elements";
		}

		@Override
		public List<CompilerElement> getModelData() {
			return tableElements;
		}

		@Override
		public Object getColumnValueForRow(CompilerElement t, int columnIndex) {
			switch (columnIndex) {
				case EXTENSION_TYPE_COLUMN:
					return t.type.getTagName();
				case NAME_COLUMN:
					return t.name;
				case STATUS_COLUMN:
					if (t.status == Status.CORE) {
						return "";
					}
					return t.status.formalName;
			}
			return "Unknown column!";
		}
	}

	private class CompilerElementTable extends GTable {
		private ElementRenderer renderer;

		CompilerElementTable(TableModel model) {
			super(model);
			renderer = new ElementRenderer();
		}

		@Override
		public TableCellRenderer getCellRenderer(int row, int col) {
			return renderer;
		}

	}

	private class ElementRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			if (data.isSelected()) {
				return this;
			}

			int row = data.getRowViewIndex();

			CompilerElement compilerElement = tableModel.getRowObject(row);

			if (compilerElement.status == Status.EXTENSION_ERROR) {
				setBackground(Color.pink);
			}

			return this;
		}

	}

	/**
	 *  Task for applying any accumulated changes in the list of CompilerElements for this Panel to the Program.
	 */
	public class ChangeExtensionTask extends Task {

		public ChangeExtensionTask() {
			super("Committing extension changes", true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				for (CompilerElement element : tableElements) {
					switch (element.status) {
						case CORE:
						case EXTENSION:
						case EXTENSION_ERROR:
						case EXTENSION_OVERRIDE:
							break;			// Unchanged
						case EXTENSION_REMOVE:
							specExtension.removeCompilerSpecExtension(element.optionName, monitor);
							break;
						case EXTENSION_INSTALL:
						case EXTENSION_REPLACE:
						case EXTENSION_OVERPENDING:
							specExtension.addReplaceCompilerSpecExtension(element.xmlString,
								monitor);
							break;
					}
				}
			}
			catch (LockException ex) {
				Msg.showError(this, null, "Missing Exclusive Access",
					"Do not have exclusive acces");
			}
			catch (XmlParseException | SAXException ex) {
				Msg.showError(this, null, "Failed Committing Extension Changes", ex.getMessage());
			}
			catch (CancelledException ex) {
				// User cancelled
			}
		}
	}

	private void populateElementTable() {
		tableElements = new ArrayList<>();
		CompilerSpec compilerSpec = program.getCompilerSpec();
		PrototypeModel[] models = compilerSpec.getAllModels();
		for (PrototypeModel model : models) {
			SpecExtension.Type type = SpecExtension.Type.PROTOTYPE_MODEL;
			Status status = Status.CORE;
			if (model.isProgramExtension()) {
				status = model.isErrorPlaceholder() ? Status.EXTENSION_ERROR : Status.EXTENSION;
			}
			if (model instanceof PrototypeModelMerged) {
				type = SpecExtension.Type.MERGE_MODEL;
			}
			CompilerElement compEl = new CompilerElement(model.getName(), type, status);
			tableElements.add(compEl);
		}
		PcodeInjectLibrary injectLibrary = compilerSpec.getPcodeInjectLibrary();
		String[] callFixupNames = injectLibrary.getCallFixupNames();
		for (String fixupName : callFixupNames) {
			SpecExtension.Type type = SpecExtension.Type.CALL_FIXUP;
			Status status = Status.CORE;
			if (injectLibrary.hasProgramPayload(fixupName, InjectPayload.CALLFIXUP_TYPE)) {
				status = Status.EXTENSION;
				if (injectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, fixupName)
						.isErrorPlaceholder()) {
					status = Status.EXTENSION_ERROR;
				}
			}
			CompilerElement compEl = new CompilerElement(fixupName, type, status);
			tableElements.add(compEl);
		}
		String[] callOtherNames = injectLibrary.getCallotherFixupNames();
		for (String fixupName : callOtherNames) {
			SpecExtension.Type type = SpecExtension.Type.CALLOTHER_FIXUP;
			Status status = Status.CORE;
			if (injectLibrary.hasProgramPayload(fixupName, InjectPayload.CALLOTHERFIXUP_TYPE)) {
				status = Status.EXTENSION;
				if (injectLibrary.isOverride(fixupName, InjectPayload.CALLOTHERFIXUP_TYPE)) {
					status = Status.EXTENSION_OVERRIDE;
				}
				if (injectLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, fixupName)
						.isErrorPlaceholder()) {
					status = Status.EXTENSION_ERROR;
				}
			}
			CompilerElement compEl = new CompilerElement(fixupName, type, status);
			tableElements.add(compEl);
		}
		tableElements.sort(null);
	}

	private void addListeners() {
		selectionModel = extensionTable.getSelectionModel();
		selectionModel.addListSelectionListener(new TableSelectionListener());
	}

	SpecExtensionPanel(ProgramDB program, PropertyChangeListener listener) {
		this.program = program;
		this.listener = listener;
		unappliedChanges = false;
		specExtension = new SpecExtension(program);
		createPanel();
		populateElementTable();
		addListeners();
	}

	public void apply(TaskMonitor monitor) {
		ChangeExtensionTask task = new ChangeExtensionTask();
		new TaskLauncher(task, this);
		populateElementTable();
		changesMade(false);
		tableModel.fireTableDataChanged();
	}

	/**
	 * Cancel any pending changes and reload the current table
	 */
	public void cancel() {
		populateElementTable();
		tableModel.fireTableDataChanged();
	}

	/**
	 * Size the columns.
	 */
	private void adjustTableColumns() {
		extensionTable.doLayout();
		TableColumn column =
			extensionTable.getColumn(extensionTable.getColumnName(EXTENSION_TYPE_COLUMN));
		column.setPreferredWidth(100);
		column = extensionTable.getColumn(extensionTable.getColumnName(NAME_COLUMN));
		column.setPreferredWidth(250);
		column = extensionTable.getColumn(extensionTable.getColumnName(STATUS_COLUMN));
		column.setPreferredWidth(150);
	}

	private void createPanel() {
		setLayout(new BorderLayout(10, 10));
		tableModel = new ExtensionTableModel();
		extensionTable = new CompilerElementTable(tableModel);

		JScrollPane sp = new JScrollPane(extensionTable);
		extensionTable.setPreferredScrollableViewportSize(new Dimension(400, 100));
		extensionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		adjustTableColumns();
		JPanel centerPanel = new JPanel(new BorderLayout());
		JPanel lowerPanel = createButtonPanel();
		centerPanel.add(sp, BorderLayout.CENTER);
		add(centerPanel, BorderLayout.CENTER);
		add(lowerPanel, BorderLayout.SOUTH);
	}

	private static File getStartingDir() {
		String lastDirectoryPath = Preferences.getProperty(LAST_EXPORT_DIRECTORY);
		if (lastDirectoryPath != null) {
			return new File(lastDirectoryPath);
		}

		return new File(System.getProperty("user.home"));
	}

	private static File getFileFromUser(String suggestedName) {
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component activeComponent = kfm.getActiveWindow();
		GhidraFileChooser fileChooser = new GhidraFileChooser(activeComponent);
		fileChooser.setTitle("Please Select A File");
		fileChooser.setFileFilter(FILE_FILTER);
		fileChooser.setApproveButtonText("OK");
		File startDir = getStartingDir();
		if (suggestedName != null) {
			fileChooser.setSelectedFile(new File(startDir, suggestedName));
		}
		else {
			fileChooser.setCurrentDirectory(startDir);
		}

		File selectedFile = fileChooser.getSelectedFile();

		// make sure the file has the correct extension
		if ((selectedFile != null) &&
			!selectedFile.getName().endsWith(PREFERENCES_FILE_EXTENSION)) {
			selectedFile = new File(selectedFile.getAbsolutePath() + PREFERENCES_FILE_EXTENSION);
		}

		// save off the last location to which the user navigated so we can
		// return them to that spot if they use the dialog again.
		Preferences.setProperty(LAST_EXPORT_DIRECTORY,
			fileChooser.getCurrentDirectory().getAbsolutePath());

		return selectedFile;
	}

	private static String fileToString(File file) throws IOException {
		FileReader inputReader = new FileReader(file);
		BufferedReader reader = new BufferedReader(inputReader);
		try {
			StringBuffer buffer = new StringBuffer();
			String line = null;
			while ((line = reader.readLine()) != null) {
				buffer.append(line);
				buffer.append('\n');
			}
			return buffer.toString();
		}
		finally {
			reader.close();
		}
	}

	private int findMatch(SpecExtension.Type type, String name) {
		for (int i = 0; i < tableElements.size(); ++i) {
			CompilerElement el = tableElements.get(i);
			if (el.name.equals(name) && el.type == type) {
				return i;
			}
		}
		return -1;
	}

	// signals that there are unapplied changes
	private void changesMade(boolean changes) {
		listener.propertyChange(
			new PropertyChangeEvent(this, "apply.enabled", unappliedChanges, changes));
		unappliedChanges = changes;
	}

	/**
	 * Present a file chooser, then
	 *    - Load the file as a String
	 *    - Test the validity of the file as an XML document describing an extension
	 *    - Create a new CompilerElement representing the extension OR
	 *    - Mark an existing CompilerElement as being overwritten with the new document
	 */
	private void importExtension() {
		if (!program.hasExclusiveAccess()) {
			Msg.showError(this, this, "Import Failure",
				"Must have an exclusive checkout to import a new extension");
			return;
		}
		File file = getFileFromUser(null);
		if (file == null) {
			return;
		}
		String document;
		DocInfo docInfo = null;
		Exception errMessage = null;
		try {
			document = fileToString(file).trim();
			docInfo = specExtension.testExtensionDocument(document);
			int pos = findMatch(docInfo.getType(), docInfo.getFormalName());
			Status status = Status.EXTENSION_INSTALL;
			if (pos >= 0) {
				CompilerElement previousEl = tableElements.get(pos);
				switch (previousEl.status) {
					case CORE:
						if (!docInfo.isOverride()) {
							throw new DuplicateNameException(
								"Cannot override core extension: " + previousEl.name);
						}
						status = Status.EXTENSION_OVERPENDING;
						break;
					case EXTENSION:
					case EXTENSION_ERROR:
					case EXTENSION_REMOVE:
					case EXTENSION_REPLACE:
						status = Status.EXTENSION_REPLACE;
						break;
					case EXTENSION_OVERRIDE:
					case EXTENSION_OVERPENDING:
						status = Status.EXTENSION_OVERPENDING;
						break;
					case EXTENSION_INSTALL:
						break;
				}
			}
			CompilerElement newEl =
				new CompilerElement(docInfo.getFormalName(), docInfo.getType(), status);
			newEl.xmlString = document;
			if (pos >= 0) {
				tableElements.set(pos, newEl);
			}
			else {
				tableElements.add(newEl);
			}
			tableElements.sort(null);
			changesMade(true);
			tableModel.fireTableDataChanged();
		}
		catch (Exception e) {
			errMessage = e;
		}
		if (errMessage != null) {
			Msg.showError(this, this, "Import Failure", errMessage.getMessage(), errMessage);
			return;
		}
	}

	private String getXmlString(CompilerElement element) {
		CompilerSpec compilerSpec = program.getCompilerSpec();
		PcodeInjectLibrary injectLibrary = compilerSpec.getPcodeInjectLibrary();
		InjectPayload payload;
		PrototypeModel model;
		String resultString = null;
		if (element.status == Status.CORE) {
			StringBuilder buffer = new StringBuilder();
			switch (element.type) {
				case CALL_FIXUP:
					payload = injectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, element.name);
					if (payload != null) {
						payload.saveXml(buffer);
					}
					break;
				case CALLOTHER_FIXUP:
					payload =
						injectLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, element.name);
					if (payload != null) {
						payload.saveXml(buffer);
					}
					break;
				case PROTOTYPE_MODEL:
				case MERGE_MODEL:
					model = compilerSpec.getCallingConvention(element.name);
					if (model != null) {
						model.saveXml(buffer, injectLibrary);
					}
					break;
			}
			resultString = buffer.toString();
			if (resultString.length() == 0) {
				resultString = null;
			}
		}
		else {
			resultString =
				SpecExtension.getCompilerSpecExtension(program, element.type, element.name);
		}
		return resultString;
	}

	private void exportExtension() {
		CompilerElement compilerElement = getSelectedCompilerElement();
		if (compilerElement == null) {
			return;
		}
		if (!compilerElement.isExisting()) {
			return;		// Only export existing elements
		}
		String suggestedName = compilerElement.name + PREFERENCES_FILE_EXTENSION;
		File outputFile = getFileFromUser(suggestedName);
		if (outputFile == null) {
			return;
		}
		if (outputFile.exists()) {
			int userChoice = OptionDialog.showYesNoDialog(this, "File exists.",
				"Overwrite " + outputFile.getName() + " ?");
			if (userChoice != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		String exportString = getXmlString(compilerElement);
		String errMessage = null;
		if (exportString == null) {
			errMessage = "Unable to  build document for " + compilerElement.name;
		}
		else {
			FileWriter writer = null;
			try {
				writer = new FileWriter(outputFile);
				writer.write(exportString);
				writer.close();
			}
			catch (IOException ex) {
				errMessage = "Failed to write to file: " + ex.getMessage();
			}
		}
		if (errMessage != null) {
			Msg.showError(this, this, "Export Failure", errMessage);
		}
	}

	/**
	 * Present the user with a confirmation dialog.  If confirmed, mark
	 * the selected element for removal.
	 */
	private void removeExtension() {
		if (!program.hasExclusiveAccess()) {
			Msg.showError(this, this, "Remove Failure",
				"Must have an exclusive checkout to remove an extension");
			return;
		}
		CompilerElement compilerElement = getSelectedCompilerElement();
		if (compilerElement == null) {
			return;
		}
		if (compilerElement.status == Status.EXTENSION ||
			compilerElement.status == Status.EXTENSION_ERROR) {
			int userChoice = OptionDialog.showYesNoDialog(this, "Remove Extension?",
				"Mark the extension " + compilerElement.name + " for removal?");
			if (userChoice != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		else if (compilerElement.status == Status.EXTENSION_OVERRIDE) {
			int userChoice = OptionDialog.showYesNoDialog(this, "Remove Override?",
				"Mark the override " + compilerElement.name + " for removal?");
			if (userChoice != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		else {
			return;
		}
		compilerElement.status = Status.EXTENSION_REMOVE;
		extensionTable.clearSelection();
		changesMade(true);
		tableModel.fireTableDataChanged();
	}

	private CompilerElement getSelectedCompilerElement() {
		if (selectionModel.isSelectionEmpty()) {
			return null;
		}
		int selectedRow = extensionTable.getSelectedRow();
		return tableElements.get(selectedRow);
	}

	private JPanel createButtonPanel() {
		JButton importButton = new JButton("Import...");
		importButton.setToolTipText("Load extension from an XML file");
		importButton.addActionListener(event -> {
			// give Swing a chance to repaint
			Swing.runLater(() -> {
				extensionTable.clearSelection();
				importExtension();
			});
		});

		exportButton = new JButton("Export...");
		exportButton.setToolTipText("Export extensions to an XML file");
		exportButton.addActionListener(event -> {
			// give Swing a chance to repaint
			Swing.runLater(() -> {
				exportExtension();
			});
		});

		removeButton = new JButton("Remove");
		removeButton.setToolTipText("Remove an existing extension");
		removeButton.addActionListener(event -> {
			// give Swing a chance to repaint
			Swing.runLater(() -> {
				removeExtension();
			});
		});

		JPanel containerPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		containerPanel.add(importButton);
		containerPanel.add(exportButton);
		containerPanel.add(removeButton);

		return containerPanel;
	}
}
