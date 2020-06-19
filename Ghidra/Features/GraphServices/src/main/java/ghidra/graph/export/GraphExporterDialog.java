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
import java.io.*;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.jgrapht.Graph;
import org.jgrapht.nio.GraphExporter;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GLabel;
import ghidra.framework.preferences.Preferences;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;
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

	private static GraphExportFormat lastUsedExporterFormat = GraphExportFormat.GRAPHML;  // default to GZF first time

	private JTextField filePathTextField;
	private JButton fileChooserButton;
	private GhidraComboBox<GraphExportFormat> comboBox;
	private Graph<AttributedVertex, AttributedEdge> graph;

	/**
	 * Construct a new ExporterDialog for exporting a program, optionally only exported a
	 * selected region.
	 *
	 * @param graph the graph to save
	 */
	public GraphExporterDialog(Graph<AttributedVertex, AttributedEdge> graph) {
		super("Export Graph");
		this.graph = graph;

		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation("ExporterPlugin", "Exporter_Dialog"));
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
		GraphExportFormat exporter = getSelectedExporter();
		if (exporter != null) {
			chooser.setFileFilter(
				new ExtensionFileFilter(exporter.getDefaultFileExtension(), exporter.toString()));
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

		List<GraphExportFormat> exporters = getApplicableExporters();
		comboBox = new GhidraComboBox<>(exporters.toArray(new GraphExportFormat[0]));

		GraphExportFormat defaultExporter = getDefaultExporter(exporters);
		if (defaultExporter != null) {
			comboBox.setSelectedItem(defaultExporter);
		}
		return comboBox;
	}

	private List<GraphExportFormat> getApplicableExporters() {
		return Arrays.asList(GraphExportFormat.values());
	}

	private GraphExportFormat getDefaultExporter(List<GraphExportFormat> list) {

		// first try the last one used
		for (GraphExportFormat exporter : list) {
			if (lastUsedExporterFormat.equals(exporter)) {
				return exporter;
			}
		}

		return list.isEmpty() ? null : list.get(0);
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

	private GraphExportFormat getSelectedExporter() {
		return (GraphExportFormat) comboBox.getSelectedItem();
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
		GraphExportFormat exporterFormat = getSelectedExporter();
		String extension = "." + exporterFormat.getDefaultFileExtension();
		if (!filename.toLowerCase().endsWith(extension.toLowerCase())) {
			return filename + extension;
		}
		return filename;
	}

	@Override
	protected void okCallback() {
		lastUsedExporterFormat = getSelectedExporter();
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
		GraphExportFormat exporterFormat = getSelectedExporter();
		File outputFile = getSelectedOutputFile();

		try {
			if (outputFile.exists() &&
				OptionDialog.showOptionDialog(getComponent(), "Overwrite Existing File?",
					"The file " + outputFile + " already exists.\nDo you want to overwrite it?",
					"Overwrite", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
				return false;
			}
			Writer writer = new FileWriter(outputFile);

			GraphExporter<AttributedVertex, AttributedEdge> exporter =
				AttributedGraphExporterFactory.getExporter(exporterFormat);

			exporter.exportGraph(graph, writer);

			displaySummaryResults(exporterFormat);
			return true;
		}
		catch (Exception e) {
			Msg.error(this, "Exception exporting", e);
			SystemUtilities.runSwingLater(() -> setStatusText(
				"Exception exporting: " + e.getMessage() + ".  If null, see log for details."));
		}
		return false;
	}

	/**
	 * TODO: this does nothing useful
	 * @param exporter the export format
	 */
	private void displaySummaryResults(GraphExportFormat exporter) {
		File outputFile = getSelectedOutputFile();
		String results =
			"Destination file:       " +
				"Destination file Size:  " +
				outputFile.length() + "\n" +
				"Format:                 " +
				exporter.toString() + "\n\n";

		String log = exporter.toString();
		if (log != null) {
			results += log;
		}
	}

	// for testing
	public void setOutputFile(String outputFilePath) {
		filePathTextField.setText(outputFilePath);
	}

	// for testing
	public void setExportFormat(GraphExportFormat format) {
		comboBox.setSelectedItem(format);
	}

}
