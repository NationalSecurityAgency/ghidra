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
package pdb.symbolserver.ui;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import pdb.symbolserver.SymbolServerInstanceCreatorRegistry;
import pdb.symbolserver.SymbolServerService;

/**
 * Dialog that allows the user to configure the Pdb search locations and symbol directory
 */
public class ConfigPdbDialog extends DialogComponentProvider {

	public static void showSymbolServerConfig() {
		ConfigPdbDialog choosePdbDialog = new ConfigPdbDialog();
		DockingWindowManager.showDialog(choosePdbDialog);
	}

	private SymbolServerPanel symbolServerConfigPanel;

	public ConfigPdbDialog() {
		super("Configure Symbol Server Search", true, false, true, false);

		build();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		if (symbolServerConfigPanel.isConfigChanged() &&
			OptionDialog.showYesNoDialog(getComponent(),
				"Save Configuration",
				"Symbol server configuration changed.  Save?") == OptionDialog.YES_OPTION) {
			symbolServerConfigPanel.saveConfig();
		}
		close();
	}

	private void build() {
		symbolServerConfigPanel = new SymbolServerPanel(this::onSymbolServerServiceChange,
			SymbolServerInstanceCreatorRegistry.getInstance().getContext());

		addButtons();
		addWorkPanel(symbolServerConfigPanel);
		setRememberSize(false);
		okButton.setEnabled(symbolServerConfigPanel.getSymbolServerService() != null);
		setMinimumSize(400, 250);
	}

	private void onSymbolServerServiceChange(SymbolServerService newService) {
		okButton.setEnabled(newService != null);
		rootPanel.revalidate();
	}

	private void addButtons() {
		addOKButton();
		addCancelButton();
		setDefaultButton(cancelButton);
	}
}
