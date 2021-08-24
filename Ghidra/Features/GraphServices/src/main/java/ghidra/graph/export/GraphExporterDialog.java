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
package ghidra.graph.export;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GLabel;
import ghidra.framework.preferences.Preferences;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedGraphExporter;
import ghidra.util.*;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Dialog for exporting a program from a Ghidra project to an external file in one of the
 * supported export formats.
 */

public class GraphExporterDialog extends DialogComponentProvider {

	private static String lastUsedExporterName = "JSON";  // default to JSON first time

	private JTextField filePathTextField;
	private JButton fileChooserButton;
	private GhidraComboBox<AttributedGraphExporter> comboBox;
	private final AttributedGraph graph;

	private List<AttributedGraphExporter> exporters;

	/**
	 * Construct a new ExporterDialog for exporting a program, optionally only exported a
	 * selected region.
	 *
	 * @param graph the graph to save
	 * @param exporters the list of known exporters
	 */
	public GraphExporterDialog(AttributedGraph graph, List<AttributedGraphExporter> exporters) {
		super("Export Graph");
		this.graph = graph;
		this.exporters = exporters;

		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation("GraphServices", "Graph_Exporter"));
		validate();
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
		return panel;
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

	public void setFilePath(String filePath) {
		filePathTextField.setText(filePath);
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
		String name = "graph";
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
		AttributedGraphExporter exporter = getSelectedExporter();
		if (exporter != null) {
			chooser.setFileFilter(
				new ExtensionFileFilter(exporter.getFileExtension(), exporter.toString()));
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

		comboBox =
			new GhidraComboBox<>(exporters.toArray(new AttributedGraphExporter[exporters.size()]));

		AttributedGraphExporter defaultExporter = getDefaultExporter();
		if (defaultExporter != null) {
			comboBox.setSelectedItem(defaultExporter);
		}
		return comboBox;
	}

	private AttributedGraphExporter getDefaultExporter() {

		// first try the last one used
		for (AttributedGraphExporter exporter : exporters) {
			if (lastUsedExporterName.equals(exporter.getName())) {
				return exporter;
			}
		}

		return exporters.isEmpty() ? null : exporters.get(0);
	}

	private void validate() {
		setOkEnabled(false);
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
		setOkEnabled(true);
	}

	private AttributedGraphExporter getSelectedExporter() {
		return (AttributedGraphExporter) comboBox.getSelectedItem();
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
		AttributedGraphExporter exporter = getSelectedExporter();
		String extension = "." + exporter.getFileExtension();
		if (!filename.toLowerCase().endsWith(extension.toLowerCase())) {
			return filename + extension;
		}
		return filename;
	}

	@Override
	protected void okCallback() {
		setLastExportDirectory(getSelectedOutputFile());
		if (doExport()) {
			close();
		}
	}

	private boolean doExport() {

		AtomicBoolean success = new AtomicBoolean();
		TaskLauncher.launchModal("Exporting Graph",
			monitor -> success.set(tryExport(monitor)));
		return success.get();
	}

	private boolean tryExport(TaskMonitor monitor) {
		AttributedGraphExporter exporter = getSelectedExporter();
		File outputFile = getSelectedOutputFile();

		if (outputFile.exists() &&
			OptionDialog.showOptionDialog(getComponent(), "Overwrite Existing File?",
				"The file " + outputFile + " already exists.\nDo you want to overwrite it?",
				"Overwrite", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
			return false;
		}

		try {
			exporter.exportGraph(graph, outputFile);
			return true;
		}
		catch (Exception e) {
			Msg.error(this, "Exception exporting", e);
			SystemUtilities.runSwingLater(() -> setStatusText(
				"Exception exporting: " + e.getMessage() + ".  If null, see log for details."));
		}
		return false;
	}

	// for testing
	public void setOutputFile(String outputFilePath) {
		filePathTextField.setText(outputFilePath);
	}

	// for testing
	public void setExporter(AttributedGraphExporter exporter) {
		comboBox.setSelectedItem(exporter);
	}

}
