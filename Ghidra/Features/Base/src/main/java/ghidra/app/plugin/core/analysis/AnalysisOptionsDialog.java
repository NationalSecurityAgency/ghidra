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
package ghidra.app.plugin.core.analysis;

import java.util.List;

import docking.DialogComponentProvider;
import ghidra.framework.options.EditorStateFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Dialog to show the panel for the auto analysis options.
 *
 */
public class AnalysisOptionsDialog extends DialogComponentProvider {
	private boolean doAnalysis;
	private AnalysisPanel panel;
	private EditorStateFactory editorStateFactory = new EditorStateFactory();

	/**
	 * Constructor
	 * 
	 * @param program the program to run analysis on
	 */
	AnalysisOptionsDialog(Program program) {
		this(List.of(program));
	}

	/**
	 * Constructor 
	 * 
	 * @param programs the set of programs to run analysis on
	 */
	AnalysisOptionsDialog(List<Program> programs) {
		super("Analysis Options");
		setHelpLocation(new HelpLocation("AutoAnalysisPlugin", "AnalysisOptions"));
		panel = new AnalysisPanel(programs, editorStateFactory);

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setOkButtonText("Analyze");
		okButton.setMnemonic('A');
		setOkEnabled(true);
		setPreferredSize(1000, 600);
		setRememberSize(true);
	}

	@Override
	public void okCallback() {
		try {
			panel.applyChanges();
			doAnalysis = true;
			close();
		}
		catch (Exception e) {
			Msg.showError(this, panel, "Error Setting Analysis Options", e.getMessage(), e);
		}
	}

	boolean wasAnalyzeButtonSelected() {
		return doAnalysis;
	}

}

