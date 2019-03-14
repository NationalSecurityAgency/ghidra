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
import java.math.BigInteger;

import org.xml.sax.SAXException;

import docking.widgets.filechooser.GhidraFileChooser;
import generic.jar.ResourceFile;
import ghidra.app.analyzers.FunctionStartAnalyzer.ContextAction;
import ghidra.bitpatterns.info.ContextRegisterFilter;
import ghidra.bitpatterns.info.PatternType;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * This class is an {@link ActionListener} for importing function start patterns from an XML file
 */
public class ImportPatternFileActionListener implements ActionListener {
	private static final String XML_IMPORT_DIR_PROPERTY =
		"ImportPatternFileActionListener_XML_IMPORT_DIR_PROPERTY";

	private Component component;
	private FunctionBitPatternsExplorerPlugin plugin;

	/**
	 * Constructs an {@link ActionListener} for importing XML files
	 * @param plugin associated {@link FunctionBitPatternsExplorerPlugin}
	 * @param component parent
	 */
	public ImportPatternFileActionListener(FunctionBitPatternsExplorerPlugin plugin,
			Component component) {
		this.component = component;
		this.plugin = plugin;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		GhidraFileChooser fileChooser = new GhidraFileChooser(component);

		fileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		fileChooser.setTitle("Select Pattern File");
		String baseDir = Preferences.getProperty(XML_IMPORT_DIR_PROPERTY);
		if (baseDir != null) {
			fileChooser.setCurrentDirectory(new File(baseDir));
		}
		ExtensionFileFilter xmlFilter = new ExtensionFileFilter("xml", "XML Files");
		fileChooser.setFileFilter(xmlFilter);
		File patternFile = fileChooser.getSelectedFile();
		if (fileChooser.wasCancelled() || patternFile == null) {
			return;
		}
		Preferences.setProperty(XML_IMPORT_DIR_PROPERTY,
			fileChooser.getCurrentDirectory().getAbsolutePath());
		Preferences.store();
		//only clear the patterns if new patterns are loaded from a file
		ResourceFile resource = new ResourceFile(patternFile);
		try {
			PatternPairSet pairSet = ClipboardPanel.parsePatternPairSet(resource);
			if (pairSet == null) {
				return;
			}
			plugin.clearPatterns();
			for (DittedBitSequence pre : pairSet.getPreSequences()) {
				PatternInfoRowObject preRow = new PatternInfoRowObject(PatternType.PRE, pre, null);
				plugin.addPattern(preRow);
			}
			//post patterns can have alignment and context register restrictions
			processPostPatterns(pairSet);
		}
		catch (IOException | SAXException e1) {
			Msg.showError(this, component, "Import Error",
				"Error Importing file " + patternFile.getAbsolutePath(), e1);
		}
		plugin.updateClipboard();
	}

	private void processPostPatterns(PatternPairSet pairSet) {
		//post patterns can have alignment and context register restrictions
		for (Pattern post : pairSet.getPostPatterns()) {
			int alignment = 0;
			for (PostRule postRule : post.getPostRules()) {
				if (postRule instanceof AlignRule) {
					AlignRule align = (AlignRule) postRule;
					alignment = align.getAlignMask();
					break; //there should only be one alignment constraint
				}
			}
			ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
			for (MatchAction matchAction : post.getMatchActions()) {
				if (matchAction instanceof ContextAction) {
					ContextAction contextAction = (ContextAction) matchAction;
					String cReg = contextAction.getName();
					BigInteger value = contextAction.getValue();
					cRegFilter.addRegAndValueToFilter(cReg, value);
				}
			}
			PatternInfoRowObject postRow = new PatternInfoRowObject(PatternType.FIRST, post,
				cRegFilter.getValueMap().isEmpty() ? null : cRegFilter);
			if (alignment != 0) {
				postRow.setAlignment(alignment + 1);
			}
			plugin.addPattern(postRow);
		}
	}
}
