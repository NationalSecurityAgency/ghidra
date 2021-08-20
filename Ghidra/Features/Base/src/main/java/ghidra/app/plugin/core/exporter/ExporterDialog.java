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
package ghidra.app.plugin.core.exporter;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.help.AboutDomainObjectUtils;
import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.*;

/**
 * Dialog for exporting a program from a Ghidra project to an external file in one of the
 * supported export formats.
 */

public class ExporterDialog extends DialogComponentProvider implements AddressFactoryService {

	private static final String XML_WARNING =
		"   Warning: XML is lossy and intended only for transfering data to external tools. GZF is the recommended format for saving and sharing program data.";

	private static String lastUsedExporterName = "Ghidra Zip File";  // default to GZF first time

	private JButton optionsButton;
	private ProgramSelection currentSelection;
	private JCheckBox selectionCheckBox;
	private JTextField filePathTextField;
	private JButton fileChooserButton;
	private GhidraComboBox<Exporter> comboBox;
	private final DomainFile domainFile;
	private DomainObject domainObject;
	private List<Option> options;
	private PluginTool tool;

	private JLabel selectionOnlyLabel;

	/**
	 * Construct a new ExporterDialog for exporting an entire program.
	 *
	 * @param tool the tool that launched this dialog.
	 * @param domainFile the program to export
	 */
	public ExporterDialog(PluginTool tool, DomainFile domainFile) {
		this(tool, domainFile, null, null);
	}

	/**
	 * Construct a new ExporterDialog for exporting a program, optionally only exported a
	 * selected region.
	 *
	 * @param tool the tool that launched this dialog.
	 * @param domainFile the program file to export.
	 * @param domainObject the program to export if already open, otherwise null.
	 * @param selection the current program selection.
	 */
	public ExporterDialog(PluginTool tool, DomainFile domainFile, DomainObject domainObject,
			ProgramSelection selection) {
		super("Export " + domainFile.getName());
		this.tool = tool;
		this.domainFile = domainFile;
		this.domainObject = domainObject;
		this.currentSelection = selection;
		if (domainObject != null) {
			domainObject.addConsumer(this);
		}

		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation("ExporterPlugin", "Exporter_Dialog"));

		// This dialog is temporary and will be closed when the task is finished.  Mark
		// it transient so no other windows will be parented to this dialog.
		setTransient(true);

		// need to initialize a few things
		selectedFormatChanged();
		validate();
	}

	@Override
	public void close() {
		super.close();
		if (domainObject != null) {
			domainObject.release(this);
		}
	}

	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildMainPanel());
		panel.add(buildButtonPanel());
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		JPanel innerPanel = new JPanel(new VerticalLayout(5));
		innerPanel.add(buildOptionsButton());
		panel.add(buildSelectionCheckboxPanel(), BorderLayout.WEST);
		panel.add(innerPanel, BorderLayout.EAST);
		return panel;
	}

	private Component buildOptionsButton() {
		optionsButton = new JButton("Options...");
		optionsButton.addActionListener(e -> showOptions());
		return optionsButton;
	}

	private void showOptions() {
		OptionValidator validator = optionList -> {
			try {
				getSelectedExporter().setOptions(optionList);
				return null;
			}
			catch (OptionException e) {
				return e.getMessage();   // OptionExceptions should have good message as to what is wrong
			}
			catch (Exception e) {
				return "Unexpected exception validating options: " + e.getMessage();
			}
		};
		OptionsDialog optionsDialog = new OptionsDialog(options, validator, this);
		optionsDialog.setHelpLocation(
			new HelpLocation("ExporterPlugin", getAnchorForSelectedFormat()));
		tool.showDialog(optionsDialog);
		if (!optionsDialog.wasCancelled()) {
			options = optionsDialog.getOptions();
		}

	}

	private String getAnchorForSelectedFormat() {
		Exporter selectedExporter = getSelectedExporter();
		String exporterName = selectedExporter.getName();
		return "Options_" + exporterName;
	}

	private Component buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(new GLabel("Format: ", SwingConstants.RIGHT));
		panel.add(buildFormatChooser());
		panel.add(new GLabel("Output File: ", SwingConstants.RIGHT));
		panel.add(buildFilePanel());
		return panel;
	}

	private Component buildSelectionCheckboxPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		selectionOnlyLabel = new GLabel("Selection Only:");
		panel.add(selectionOnlyLabel);
		panel.add(buildSelectionCheckbox());
		return panel;
	}

	private Component buildSelectionCheckbox() {
		selectionCheckBox = new GCheckBox("");
		updateSelectionCheckbox();
		return selectionCheckBox;
	}

	private Component buildFilePanel() {
		filePathTextField = new JTextField();
		filePathTextField.setName("OUTPUT_FILE_TEXTFIELD");
		filePathTextField.setText(getFileName());
		filePathTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				validate();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				validate();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				validate();
			}

		});

		fileChooserButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		fileChooserButton.addActionListener(e -> chooseDestinationFile());

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(filePathTextField, BorderLayout.CENTER);
		panel.add(fileChooserButton, BorderLayout.EAST);
		return panel;
	}

	private String getFileName() {
		String name = domainFile.getName();
		File lastDir = getLastExportDirectory();
		return lastDir.getAbsolutePath() + File.separator + name;
	}

	private void chooseDestinationFile() {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setSelectedFile(getLastExportDirectory());
		chooser.setTitle("Select Output File");
		chooser.setApproveButtonText("Select Output File");
		chooser.setApproveButtonToolTipText("Select File");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		Exporter exporter = getSelectedExporter();
		if (exporter != null && exporter.getDefaultFileExtension() != null) {
			chooser.setFileFilter(
				new ExtensionFileFilter(exporter.getDefaultFileExtension(), exporter.getName()));
		}
		String filePath = filePathTextField.getText().trim();
		File currentFile = filePath.isEmpty() ? null : new File(filePath);
		if (currentFile != null) {
			chooser.setSelectedFile(currentFile);
		}
		File file = chooser.getSelectedFile();
		if (file != null) {
			setLastExportDirectory(file);
			filePathTextField.setText(file.getAbsolutePath());
		}
	}

	private void setLastExportDirectory(File file) {
		Preferences.setProperty(Preferences.LAST_EXPORT_DIRECTORY, file.getParent());
		Preferences.store();
	}

	private File getLastExportDirectory() {
		String lastDirStr = Preferences.getProperty(Preferences.LAST_EXPORT_DIRECTORY,
			System.getProperty("user.home"), true);
		return new File(lastDirStr);
	}

	private Component buildFormatChooser() {

		List<Exporter> exporters = getApplicableExporters();
		comboBox = new GhidraComboBox<>(new Vector<>(exporters));

		Exporter defaultExporter = getDefaultExporter(exporters);
		if (defaultExporter != null) {
			comboBox.setSelectedItem(defaultExporter);
		}
		comboBox.addItemListener(e -> selectedFormatChanged());
		return comboBox;
	}

	private List<Exporter> getApplicableExporters() {
		List<Exporter> list = new ArrayList<>(ClassSearcher.getInstances(Exporter.class));
		Class<? extends DomainObject> domainObjectClass = domainFile.getDomainObjectClass();
		list.removeIf(exporter -> !exporter.canExportDomainObject(domainObjectClass));
		Collections.sort(list, (o1, o2) -> o1.toString().compareTo(o2.toString()));
		return list;
	}

	private Exporter getDefaultExporter(List<Exporter> list) {

		// first try the last one used
		for (Exporter exporter : list) {
			if (lastUsedExporterName.equals(exporter.getName())) {
				return exporter;
			}
		}

		return list.isEmpty() ? null : list.get(0);
	}

	private void selectedFormatChanged() {
		Exporter selectedExporter = getSelectedExporter();
		if (selectedExporter != null) {
			options = selectedExporter.getOptions(() -> getDomainObject(TaskMonitor.DUMMY));
		}
		validate();
		updateSelectionCheckbox();
	}

	private void updateSelectionCheckbox() {
		boolean shouldEnableCheckbox = shouldEnableCheckbox();
		selectionCheckBox.setSelected(shouldEnableCheckbox);
		selectionCheckBox.setEnabled(shouldEnableCheckbox);
		selectionOnlyLabel.setEnabled(shouldEnableCheckbox);
	}

	private boolean shouldEnableCheckbox() {
		if (currentSelection == null || currentSelection.isEmpty()) {
			return false;
		}
		Exporter selectedExporter = getSelectedExporter();
		return selectedExporter != null && selectedExporter.supportsPartialExport();
	}

	private void validate() {
		setOkEnabled(false);
		optionsButton.setEnabled(hasOptions());
		setStatusText("");
		if (getSelectedExporter() == null) {
			setStatusText("Please select an exporter format.");
			return;
		}
		String fileToExportInto = filePathTextField.getText();
		if (fileToExportInto.length() == 0) {
			setStatusText("Please enter a destination file.");
			return;
		}
		File file = new File(fileToExportInto);
		if (file.isDirectory()) {
			setStatusText("The specified output file is a directory.");
			return;
		}
		if (file.exists() && !file.canWrite()) {
			setStatusText("The specified output file is read-only.");
			return;
		}
		if (getSelectedExporter().getName().contains("XML")) {
			setStatusText(XML_WARNING);
		}
		setOkEnabled(true);
	}

	private boolean hasOptions() {
		return options != null && !options.isEmpty();
	}

	private Exporter getSelectedExporter() {
		return (Exporter) comboBox.getSelectedItem();
	}

	private File getSelectedOutputFile() {
		String filename = appendExporterFileExtension(filePathTextField.getText().trim());
		File outputFileName = new File(filename);
		if (outputFileName.getParent() == null) {
			File defaultParent = new File(System.getProperty("user.home"));
			outputFileName = new File(defaultParent, filename);
		}
		return outputFileName;
	}

	private String appendExporterFileExtension(String filename) {
		Exporter exporter = getSelectedExporter();
		String extension = exporter.getDefaultFileExtension();
		if (extension.isEmpty()) {
			return filename;
		}
		extension = "." + extension;
		if (!filename.toLowerCase().endsWith(extension.toLowerCase())) {
			return filename + extension;
		}
		return filename;
	}

	@Override
	protected void okCallback() {
		lastUsedExporterName = getSelectedExporter().getName();
		setLastExportDirectory(getSelectedOutputFile());
		if (doExport()) {
			close();
		}
	}

	private DomainObject getDomainObject(TaskMonitor taskMonitor) {
		if (domainObject == null) {
			if (SystemUtilities.isEventDispatchThread()) {
				TaskLauncher.launchModal("Opening File: " + domainFile.getName(),
					monitor -> doOpenFile(monitor));
			}
			else {
				doOpenFile(taskMonitor);
			}
		}
		return domainObject;
	}

	private void doOpenFile(TaskMonitor monitor) {
		try {
			domainObject = domainFile.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION,
				TaskMonitor.DUMMY);
		}
		catch (VersionException | CancelledException | IOException e) {
			Msg.showError(this, getComponent(), "Error Opening File",
				"Could not open file: " + domainFile.getName() +
					"\nThis file may need to be upgraded! Try opening it in a tool first.");
		}
	}

	/**
	 * Gets the address factory for the program to be exported, opening it if necessary.
	 */
	@Override
	public AddressFactory getAddressFactory() {
		DomainObject dobj = getDomainObject(TaskMonitor.DUMMY);
		if (dobj instanceof Program) {
			return ((Program) domainObject).getAddressFactory();
		}
		return null;
	}

	private boolean doExport() {

		ExportTask task = new ExportTask();
		TaskLauncher.launch(task);
		task.showResults();
		return task.getSuccess();
	}

	private class ExportTask extends Task {

		private boolean success;
		private boolean showResults;
		private Exporter exporter;
		private DomainObject exportedDomainObject;

		public ExportTask() {
			super("Export " + domainFile.getName(), true, true, true, false);
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			exporter = getSelectedExporter();

			exporter.setExporterServiceProvider(tool);
			exportedDomainObject = getDomainObject(monitor);
			if (exportedDomainObject == null) {
				return;
			}
			ProgramSelection selection = getApplicableProgramSeletion();
			File outputFile = getSelectedOutputFile();

			try {
				if (outputFile.exists() &&
					OptionDialog.showOptionDialog(getComponent(), "Overwrite Existing File?",
						"The file " + outputFile + " already exists.\nDo you want to overwrite it?",
						"Overwrite", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
					return;
				}
				if (options != null) {
					exporter.setOptions(options);
				}
				success = exporter.export(outputFile, exportedDomainObject, selection, monitor);
				showResults = true;
			}
			catch (Exception e) {
				Msg.error(this, "Exception exporting", e);
				SystemUtilities.runSwingLater(() -> setStatusText(
					"Exception exporting: " + e.getMessage() + ".  If null, see log for details."));
			}
		}

		void showResults() {
			if (showResults) {
				displaySummaryResults(exporter, exportedDomainObject);
			}
		}

		boolean getSuccess() {
			return success;
		}
	}

	private boolean tryExport(TaskMonitor monitor) {
		Exporter exporter = getSelectedExporter();

		exporter.setExporterServiceProvider(tool);
		DomainObject dobj = getDomainObject(monitor);
		if (dobj == null) {
			return false;
		}
		ProgramSelection selection = getApplicableProgramSeletion();
		File outputFile = getSelectedOutputFile();

		try {
			if (outputFile.exists() &&
				OptionDialog.showOptionDialog(getComponent(), "Overwrite Existing File?",
					"The file " + outputFile + " already exists.\nDo you want to overwrite it?",
					"Overwrite", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
				return false;
			}
			if (options != null) {
				exporter.setOptions(options);
			}
			boolean success = exporter.export(outputFile, dobj, selection, monitor);
			displaySummaryResults(exporter, dobj);
			return success;
		}
		catch (Exception e) {
			Msg.error(this, "Exception exporting", e);
			SystemUtilities.runSwingLater(() -> setStatusText(
				"Exception exporting: " + e.getMessage() + ".  If null, see log for details."));
		}
		return false;
	}

	private ProgramSelection getApplicableProgramSeletion() {
		if (selectionCheckBox.isSelected()) {
			return currentSelection;
		}
		return null;
	}

	private void displaySummaryResults(Exporter exporter, DomainObject obj) {
		File outputFile = getSelectedOutputFile();
		StringBuffer resultsBuffer = new StringBuffer();

		resultsBuffer.append("Destination file:       " + outputFile.getAbsolutePath() + "\n\n");
		resultsBuffer.append("Destination file Size:  " + outputFile.length() + "\n");
		resultsBuffer.append("Format:                 " + exporter.getName() + "\n\n");

		MessageLog log = exporter.getMessageLog();
		resultsBuffer.append(log.toString());

		HelpLocation helpLocation = new HelpLocation(GenericHelpTopics.ABOUT, "About_Program");

		Object tmpConsumer = new Object();
		obj.addConsumer(tmpConsumer);
		Swing.runLater(() -> {
			try {
				AboutDomainObjectUtils.displayInformation(tool, obj.getDomainFile(),
					obj.getMetadata(), "Export Results Summary", resultsBuffer.toString(),
					helpLocation);
			}
			finally {
				obj.release(tmpConsumer);
			}
		});

	}

//==================================================================================================
// Methods for Testing
//==================================================================================================

	JCheckBox getSelectionCheckBox() {
		return selectionCheckBox;
	}

	JComboBox<Exporter> getExporterComboBox() {
		return comboBox;
	}

	JTextField getOutputFileTextField() {
		return filePathTextField;
	}

	public List<Option> getOptions() {
		return options;
	}
}
