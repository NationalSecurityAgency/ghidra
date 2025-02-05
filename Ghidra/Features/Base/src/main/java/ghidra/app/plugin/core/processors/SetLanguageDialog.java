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
package ghidra.app.plugin.core.processors;

import javax.swing.BorderFactory;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugin.importer.*;
import ghidra.plugin.importer.LcsSelectionEvent.Type;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class SetLanguageDialog extends DialogComponentProvider {

	private NewLanguagePanel selectLangPanel;
	private PluginTool tool;
	private LanguageCompilerSpecPair currentLcsPair;

	private LanguageID dialogLanguageID;
	private CompilerSpecID dialogCompilerSpecID;

	private LcsSelectionListener listener = e -> {
		languageSelected(e.getLcs());
		maybePressOk(e);
	};

	/**
	 * Construct set Language/Compiler-Spec dialog
	 * @param tool parent tool
	 * @param programArch current program architecture or null
	 * @param title dialog title
	 */
	public SetLanguageDialog(PluginTool tool, ProgramArchitecture programArch, String title) {
		this(tool, programArch != null ? programArch.getLanguageCompilerSpecPair() : null, title);
	}

	/**
	 * Construct set Language/Compiler-Spec dialog
	 * @param tool parent tool
	 * @param languageId initial language ID or null
	 * @param compilerSpecId initial Compiler-Spec ID or null
	 * @param title dialog title
	 */
	public SetLanguageDialog(PluginTool tool, String languageId, String compilerSpecId,
			String title) {
		this(tool, getLanguageCompilerSpecPair(languageId, compilerSpecId), title);
	}

	/**
	 * Construct set Language/Compiler-Spec dialog
	 * @param tool parent tool
	 * @param lcsPair language/compiler-spec ID pair or null
	 * @param title dialog title
	 */
	public SetLanguageDialog(PluginTool tool, LanguageCompilerSpecPair lcsPair, String title) {
		super(title, true, true, true, false);
		currentLcsPair = lcsPair;
		this.tool = tool;

		selectLangPanel = new NewLanguagePanel();

		if (lcsPair != null) {
			selectLangPanel.setSelectedLcsPair(lcsPair);
		}

		selectLangPanel.addSelectionListener(listener);

		selectLangPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		addWorkPanel(selectLangPanel);
		addOKButton();
		addCancelButton();

		setOkEnabled(false);
		setHelpLocation(new HelpLocation("LanguageProviderPlugin", "set language"));
		selectLangPanel.setShowRecommendedCheckbox(false);

		languageSelected(null); // kick to establish initial button enablement
	}

	private void languageSelected(LanguageCompilerSpecPair lcs) {
		LanguageID langId = null;
		CompilerSpecID compilerSpecID = null;
		if (lcs != null) {
			langId = lcs.languageID;
			compilerSpecID = lcs.compilerSpecID;
		}

		if ((currentLcsPair != null) && (langId != null) &&
			(langId.equals(currentLcsPair.getLanguageID()))) {
			if (compilerSpecID != null &&
				compilerSpecID.equals(currentLcsPair.getCompilerSpecID())) {
				setStatusText("Please select a different Language or Compiler Spec.");
				setOkEnabled(false);
			}
			else {
				setStatusText(null);
				setOkEnabled(true);
			}
			return;
		}

		setStatusText(null);
		setOkEnabled(langId != null);
	}

	private void maybePressOk(LcsSelectionEvent e) {
		if (e.getType() == Type.PICKED && isOKEnabled()) {
			// the user picked (i.e., double-clicked) a language and it is valid, so use it
			okCallback();
		}
	}

	private static LanguageCompilerSpecPair getLanguageCompilerSpecPair(String languageIdStr,
			String compilerSpecIdStr) {
		if (languageIdStr == null) {
			return null;
		}
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		try {
			LanguageID languageId = new LanguageID(languageIdStr);
			LanguageDescription descr = languageService.getLanguageDescription(languageId);
			CompilerSpecID compilerSpecId = new CompilerSpecID(compilerSpecIdStr);
			try {
				descr.getCompilerSpecDescriptionByID(compilerSpecId);
			}
			catch (CompilerSpecNotFoundException e) {
				Msg.warn(SetLanguageDialog.class, e.getMessage());
			}
			return new LanguageCompilerSpecPair(languageId, compilerSpecId);
		}
		catch (LanguageNotFoundException e) {
			Msg.warn(SetLanguageDialog.class, e.getMessage());
			return null;
		}
	}

	public LanguageID getLanguageDescriptionID() {
		tool.showDialog(this);
		return dialogLanguageID;
	}

	public CompilerSpecID getCompilerSpecDescriptionID() {
		return dialogCompilerSpecID;
	}

	@Override
	protected void okCallback() {
		LanguageCompilerSpecPair selectedLcsPair = selectLangPanel.getSelectedLcsPair();
		if (selectedLcsPair == null) {
			dialogLanguageID = null;
			dialogCompilerSpecID = null;
		}
		else {
			dialogLanguageID = selectedLcsPair.languageID;
			dialogCompilerSpecID = selectedLcsPair.compilerSpecID;
		}
		close();
	}
}
