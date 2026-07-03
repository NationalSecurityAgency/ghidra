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
package ghidra.features.codecompare.functiongraph.actions;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.features.codecompare.functiongraph.FgDisplay;
import ghidra.util.HelpLocation;

public class FgResetGraphAction extends AbstractFgAction {

	private FgDisplay display;

	public FgResetGraphAction(FgDisplay display) {
		super(display, "Reset Graph");
		this.display = display;

		setPopupMenuData(new MenuData(new String[] { "Reset Graph" }));

		setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Function_Graph_Reload_Graph"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		FGController controller = display.getController();
		JComponent component = controller.getViewComponent();
		int choice = OptionDialog.showYesNoDialog(component, "Reset Graph?",
			"<html>Erase all vertex position and grouping information?");
		if (choice != OptionDialog.YES_OPTION) {
			return;
		}

		controller.resetGraph();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!super.isEnabledForContext(context)) {
			return false;
		}
		FGController controller = display.getController();
		return controller.hasResults();
	}
}
