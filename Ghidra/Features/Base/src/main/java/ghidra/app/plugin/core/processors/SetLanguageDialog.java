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
import ghidra.plugin.importer.LcsSelectionListener;
import ghidra.plugin.importer.NewLanguagePanel;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.HelpLocation;

public class SetLanguageDialog extends DialogComponentProvider {

	private NewLanguagePanel selectLangPanel;
	private LanguageService langService;
	private PluginTool tool;
	private Program currProgram;

	private LanguageID dialogLanguageDescID;
	private CompilerSpecID dialogCompilerSpecDescID;

	LcsSelectionListener listener = e -> {
		LanguageID langID = null;
		CompilerSpecID compilerSpecID = null;
		if (e.selection != null) {
			langID = e.selection.languageID;
			compilerSpecID = e.selection.compilerSpecID;
		}
		if ((langID != null) && (langID.equals(currProgram.getLanguageID()))) {
			if ((compilerSpecID != null) &&
				(compilerSpecID.equals(currProgram.getCompilerSpec().getCompilerSpecID()))) {
				//selectLangPanel.setNotificationText("Please select a different Language or Compiler Spec.");
				setStatusText("Please select a different Language or Compiler Spec.");
				setOkEnabled(false);
			}
			else {
				//selectLangPanel.setNotificationText(null);
				setStatusText(null);
				setOkEnabled(true);
			}
			return;
		}
		//selectLangPanel.setNotificationText("Setting the language from '" + currProgram.getLanguageName() + "' to '" + langDesc.getName() + "'...");
		//selectLangPanel.setNotificationText(null);
		setStatusText(null);
		setOkEnabled(langID != null);
	};

	public SetLanguageDialog(PluginTool tool, Program program) {
		super(getTitle(program), true, true, true, false);
		currProgram = program;
		this.tool = tool;

		langService = DefaultLanguageService.getLanguageService();

		selectLangPanel = new NewLanguagePanel();

		LanguageCompilerSpecPair lcsPair = new LanguageCompilerSpecPair(currProgram.getLanguageID(),
			currProgram.getCompilerSpec().getCompilerSpecID());
		selectLangPanel.setSelectedLcsPair(lcsPair);

		selectLangPanel.addSelectionListener(listener);

		selectLangPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		addWorkPanel(selectLangPanel);
		addOKButton();
		addCancelButton();
		//getComponent().setPreferredSize(new Dimension(450, 430));
		setOkEnabled(false);
		setHelpLocation(new HelpLocation("LanguageProviderPlugin", "set language"));
		selectLangPanel.setShowRecommendedCheckbox(false);
	}

	private static String getTitle(Program program) {
		return "Set Language: " + program.getDomainFile().getName();
	}

	LanguageID getLanguageDescriptionID() {
		tool.showDialog(this);
		return dialogLanguageDescID;
	}

	CompilerSpecID getCompilerSpecDescriptionID() {
		return dialogCompilerSpecDescID;
	}

	@Override
	protected void okCallback() {
		LanguageCompilerSpecPair selectedLcsPair = selectLangPanel.getSelectedLcsPair();
		if (selectedLcsPair == null) {
			dialogLanguageDescID = null;
			dialogCompilerSpecDescID = null;
		}
		else {
			dialogLanguageDescID = selectedLcsPair.languageID;
			dialogCompilerSpecDescID = selectedLcsPair.compilerSpecID;
		}
		close();
	}
}
