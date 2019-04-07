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
//Creates an empty program using
//the language selected by the user.
//@category Program

import javax.swing.SwingUtilities;

import docking.DialogComponentProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.plugin.importer.NewLanguagePanel;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class CreateEmptyProgramScript extends GhidraScript {
	private NewLanguageDialog dialog = new NewLanguageDialog();

	@Override
	public void run() throws Exception {
		SwingUtilities.invokeAndWait(() -> state.getTool().showDialog(dialog));

		LanguageCompilerSpecPair pair = dialog.getSelectedLanguageCompilerSpecPair();
		if (pair == null) {
			println("User cancelled operation.");
		}
		else {
			try {
				Language language = pair.getLanguage();
				CompilerSpec compilerSpec = pair.getCompilerSpec();

				Program program = new ProgramDB("Untitled", language, compilerSpec, this);

				ProgramManager programManager = state.getTool().getService(ProgramManager.class);
				programManager.openProgram(program);

				program.release(this);
			}
			catch (Exception e) {
				Msg.showInfo(getClass(), null, "Error Creating New Program", e.getMessage());
			}
		}
	}

	private class NewLanguageDialog extends DialogComponentProvider {
		private NewLanguagePanel panel;
		private boolean isOK;

		NewLanguageDialog() {
			super("New Program: Select Language", true, true, true, false);

			panel = new NewLanguagePanel();
			panel.setShowRecommendedCheckbox(false);

			addWorkPanel(panel);
			addOKButton();
			addCancelButton();
			setPreferredSize(500, 250);
		}

		@Override
		protected void okCallback() {
			if (panel.getSelectedLcsPair() == null) {
				setStatusText("Please select a language.");
				return;
			}
			isOK = true;
			close();
		}

		@Override
		public void close() {
			super.close();
			panel.dispose();
		}

		@Override
		protected void cancelCallback() {
			isOK = false;
			close();
		}

		LanguageCompilerSpecPair getSelectedLanguageCompilerSpecPair() {
			return isOK ? panel.getSelectedLcsPair() : null;
		}
	}
}
