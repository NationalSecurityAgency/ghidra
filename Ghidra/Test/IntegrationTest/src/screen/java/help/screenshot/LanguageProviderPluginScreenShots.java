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
package help.screenshot;

import javax.swing.JButton;

import org.junit.Test;

import docking.widgets.OptionDialog;
import docking.widgets.table.GTableFilterPanel;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.processors.SetLanguageDialog;
import ghidra.app.plugin.processors.generic.PcodeFieldFactory;
import ghidra.app.util.viewer.field.SpacerFieldFactory;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;

public class LanguageProviderPluginScreenShots extends GhidraScreenShotGenerator {

	public LanguageProviderPluginScreenShots() {
		super();
	}

@Test
    public void testLanguages() {
		final SetLanguageDialog dialog = new SetLanguageDialog(tool, program);
		Object newLanguagePanel = getInstanceField("selectLangPanel", dialog);
		final GTableFilterPanel<?> filterPanel =
			(GTableFilterPanel<?>) getInstanceField("tableFilterPanel", newLanguagePanel);
		runSwing(new Runnable() {
			@Override
			public void run() {
				filterPanel.setFilterText("x86");
			}
		});
		showDialogWithoutBlocking(tool, dialog);
		runSwing(new Runnable() {
			@Override
			public void run() {
				dialog.setStatusText("");
				JButton okButton = (JButton) getInstanceField("okButton", dialog);
				okButton.setEnabled(true);
			}
		});
		captureDialog();
	}

@Test
    public void testPCodeDisplay() {
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		performAction("Toggle Header", "CodeBrowserPlugin", true);
		FormatManager formatMgr = (FormatManager) getInstanceField("formatMgr", plugin);
		FieldFormatModel formatModel = formatMgr.getCodeUnitFormat();
		formatModel.addRow(4);
		formatModel.addFactory(new SpacerFieldFactory(), 4, 0);
		formatModel.addFactory(new SpacerFieldFactory(), 4, 0);
		formatModel.addFactory(new SpacerFieldFactory(), 4, 0);
		formatModel.addFactory(new SpacerFieldFactory(), 4, 0);
		formatModel.addFactory(new PcodeFieldFactory(), 4, 4);

		goToListing(0x00401002, "PCode", true);

		captureProvider(CodeViewerProvider.class);
	}

@Test
    public void testWarning() {
		final String msg =
			"Setting the language can not be undone!\n \nIt is highly "
				+ "recommended that you make a copy of the\nselected file before performing "
				+ "this operation. \n \nWhen complete you can Save the results or Open the results\n"
				+ "in the CodeBrowser tool";

		runSwing(new Runnable() {
			@Override
			public void run() {
				OptionDialog.showOptionDialog(tool.getToolFrame(),
					"Set Language: " + program.getName(), msg + "\n \n" + "" +
						"\n \nDo you want to continue?", "Ok", OptionDialog.WARNING_MESSAGE);
			}
		}, false);
		captureDialog();
	}
}
