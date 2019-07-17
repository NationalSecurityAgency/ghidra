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
package ghidra.bitpatterns.gui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.bitpatterns.info.ContextRegisterFilter;
import ghidra.bitpatterns.info.PatternType;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * This class is an {@link ActionListener} used to by {@link ClipboardPanel} to export patterns to XML files
 */
public class ExportPatternFileActionListener implements ActionListener {

	private static final String BITS_PROVIDER_MESSAGE = "Enter Bit Constraints";

	private static final String XML_EXPORT_DIR_PROPERTY = "ClipboardPanel_XML_EXPORT_DIR_PROPERTY";

	private ClipboardPanel clipboardPanel;
	private Component component;

	/**
	 * Create a new {@code ExportPatternFileActionListener} for a given {@link ClipboardPanel} with
	 * parent {@link Component}
	 * @param clipboardPanel the clipboard panel
	 * @param comp the parent component
	 */
	public ExportPatternFileActionListener(ClipboardPanel clipboardPanel, Component comp) {
		this.clipboardPanel = clipboardPanel;
		component = comp;
	}

	@Override
	public void actionPerformed(ActionEvent e) {

		List<PatternInfoRowObject> selected = clipboardPanel.getLastSelectedObjects();
		if (selected.isEmpty()) {
			return;
		}
		//scan through all of them: must be at least one pre-pattern and 
		//at least one post-pattern
		boolean containsPostPattern = false;
		boolean containsPrePattern = false;
		for (PatternInfoRowObject row : selected) {
			if (row.getPatternType().equals(PatternType.FIRST)) {
				containsPostPattern = true;
			}
			if (row.getPatternType().equals(PatternType.PRE)) {
				containsPrePattern = true;
			}
		}
		if (!containsPostPattern) {
			Msg.showWarn(this, component, "No Post Pattern",
				"Selected patterns must contain at least one post pattern");
			return;
		}
		if (!containsPrePattern) {
			Msg.showWarn(this, component, "No Pre Pattern",
				"Selected patterns must contain at least one pre pattern");
			return;
		}

		boolean proceed = checkConsistencyForExport(selected);
		if (!proceed) {
			return;
		}
		GhidraFileChooser gFileChooser = new GhidraFileChooser(component);
		gFileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		ExtensionFileFilter xmlFilter = new ExtensionFileFilter("xml", "XML Files");
		gFileChooser.setFileFilter(xmlFilter);
		String baseDir = Preferences.getProperty(XML_EXPORT_DIR_PROPERTY);
		if (baseDir != null) {
			gFileChooser.setCurrentDirectory(new File(baseDir));
		}
		gFileChooser.setTitle("Select Export File");
		File outFile = gFileChooser.getSelectedFile();
		if (gFileChooser.wasCancelled() || outFile == null) {
			return;
		}
		Preferences.setProperty(XML_EXPORT_DIR_PROPERTY,
			gFileChooser.getCurrentDirectory().getAbsolutePath());
		Preferences.store();
		BitsInputDialogComponentProvider bitsProvider =
			new BitsInputDialogComponentProvider(BITS_PROVIDER_MESSAGE);
		if (bitsProvider.isCanceled()) {
			return;
		}
		int totalBits = bitsProvider.getTotalBits();
		int postBits = bitsProvider.getPostBits();
		try {
			PatternInfoRowObject.exportXMLFile(selected, outFile, postBits, totalBits);
		}
		catch (IOException e1) {
			Msg.showError(this, component, "IO Error", "IO error exporting pattern xml file", e1);
			e1.printStackTrace();
		}
	}

	//check whether the selected rows can be exported: all POST patterns (i.e., PatternType.FIRST)
	//must agree on alignment restrictions and context register filters
	private boolean checkConsistencyForExport(List<PatternInfoRowObject> selected) {
		if (selected.isEmpty()) {
			Msg.showWarn(this, component, "Export Error", "Can't export empty selection.");
			return false;
		}
		//find first POST pattern and record the alignment and context register filter
		Integer alignment = null;
		ContextRegisterFilter cRegFilter = null;
		for (PatternInfoRowObject row : selected) {
			if (!row.getPatternType().equals(PatternType.FIRST)) {
				continue;
			}
			alignment = row.getAlignment();
			cRegFilter = row.getContextRegisterFilter();
			break;
		}
		//now check that all POST patterns agree with the first POST pattern
		for (PatternInfoRowObject row : selected) {
			if (!row.getPatternType().equals(PatternType.FIRST)) {
				continue; //not a POST pattern, don't worry about it
			}
			if (!Objects.equals(alignment, row.getAlignment()) ||
				!Objects.equals(cRegFilter, row.getContextRegisterFilter())) {
				Msg.showWarn(this, component, "Export Error",
					"Selected POST rows must all agree on alignment and context registers");
				return false;
			}
		}
		return true;
	}

}
