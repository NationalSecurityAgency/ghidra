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
package ghidra.app.script;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import ghidra.plugin.importer.NewLanguagePanel;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.util.Swing;

public class SelectLanguageDialog extends DialogComponentProvider {

	private NewLanguagePanel languagePanel;
	private LanguageCompilerSpecPair selectedLcsPair;
	private boolean wasCancelled = false;

	public SelectLanguageDialog(String title, String approveButtonText) {
		super(title, true);

		languagePanel = new NewLanguagePanel(null);

		setTransient(true);
		addWorkPanel(languagePanel);
		addOKButton();
		addCancelButton();

		setOkButtonText(approveButtonText);

		// add default button
		setDefaultButton(okButton);
	}

	@Override
	protected void okCallback() {
		if (checkInput()) {
			selectedLcsPair = languagePanel.getSelectedLcsPair();
			close();
		}
	}

	@Override
	public void close() {
		super.close();
		languagePanel.dispose();
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
		wasCancelled = true;
	}

	public boolean wasCancelled() {
		return wasCancelled;
	}

	private boolean checkInput() {
		return languagePanel.getSelectedLcsPair() != null;
	}

	public void setSelectedLanguage(LanguageCompilerSpecPair language) {
		Swing.runNow(() -> languagePanel.setSelectedLcsPair(language));
	}

	public LanguageCompilerSpecPair getSelectedLanguage() {
		return selectedLcsPair;
	}

	public void show() {
		DockingWindowManager.showDialog(null, this);
	}
}
