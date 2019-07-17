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
package ghidra.plugin.importer;

import java.awt.Component;
import java.util.*;

import javax.swing.BorderFactory;
import javax.swing.SwingUtilities;

import docking.DialogComponentProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class ImporterLanguageDialog extends DialogComponentProvider {

	private PluginTool tool;
	private Collection<LoadSpec> loadSpecs;
	private NewLanguagePanel languagePanel;
	private boolean wasDialogCancelled = false;
	private LanguageCompilerSpecPair defaultSelectedLanguage;

	public ImporterLanguageDialog(Collection<LoadSpec> loadSpecs, PluginTool tool,
			LanguageCompilerSpecPair defaultSelectedLanguage) {
		super("Language", true);
		this.loadSpecs = loadSpecs;
		this.tool = tool;
		this.defaultSelectedLanguage = defaultSelectedLanguage;
		setHelpLocation(new HelpLocation("ImporterPlugin", "language_picker_dialog"));
	}

	public void show(Component parent) {
		if (SwingUtilities.isEventDispatchThread()) {
			build();
			tool.showDialog(this, parent);
		}
		else {
			try {
				SwingUtilities.invokeAndWait(new Runnable() {
					@Override
					public void run() {
						build();
						tool.showDialog(ImporterLanguageDialog.this, parent);
					}
				});
			}
			catch (Exception e) {
				Msg.error(this, e);
			}
		}
	}

	private void build() {
		languagePanel = new NewLanguagePanel();
		languagePanel.setRecommendedLcsPairsList(new ArrayList<LanguageCompilerSpecPair>());
		languagePanel.setShowAllLcsPairs(false);
		languagePanel.setBorder(
			BorderFactory.createTitledBorder(" Select Language and Compiler Specification "));
		languagePanel.addSelectionListener(new LcsSelectionListener() {
			@Override
			public void valueChanged(LcsSelectionEvent e) {
				validateFormInput();
			}
		});

		initialize();

		addWorkPanel(languagePanel);

		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);// set default button

		setOkEnabled(false);

		if (defaultSelectedLanguage != null) {
			languagePanel.setSelectedLcsPair(defaultSelectedLanguage);
		}

		validateFormInput();
	}

	private void initialize() {
		List<LanguageCompilerSpecPair> pairs = ImporterUtilities.getPairs(loadSpecs);

		languagePanel.setRecommendedLcsPairsList(pairs);
		languagePanel.setShowAllLcsPairs(pairs.isEmpty());
		languagePanel.setEnabled(true);

		selectPreferredLanguage();
	}

	@Override
	protected void okCallback() {
		if (validateFormInput()) {
			close();
		}
	}

	@Override
	protected void cancelCallback() {
		wasDialogCancelled = true;
		super.cancelCallback();
	}

	private boolean validateFormInput() {
		setOkEnabled(false);
		if (languagePanel.getSelectedLcsPair() == null) {
			setStatusText("Please select a language.");
			return false;
		}
		setStatusText("");
		setOkEnabled(true);
		return true;
	}

	private void selectPreferredLanguage() {
		List<LoadSpec> preferredLoadSpecs = new ArrayList<>();
		for (LoadSpec loadSpec : loadSpecs) {
			if (loadSpec.isPreferred()) {
				preferredLoadSpecs.add(loadSpec);
			}
		}
		if (preferredLoadSpecs.size() == 1) {
			languagePanel.setRecommendedLcsPair(
				preferredLoadSpecs.get(0).getLanguageCompilerSpec());
		}
		else {
			languagePanel.setRecommendedLcsPair(null);
		}
	}

	LanguageCompilerSpecPair getSelectedLanguage() {
		if (wasDialogCancelled) {
			return null;
		}
		return languagePanel.getSelectedLcsPair();
	}
}
