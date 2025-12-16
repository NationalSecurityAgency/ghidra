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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.features.codecompare.functiongraph.*;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

public class FgChooseFormatAction extends DockingAction {

	private FunctionGraphCodeComparisonView fgProvider;

	public FgChooseFormatAction(FunctionGraphCodeComparisonView fgProvider) {
		super("Edit Code Block Fields", fgProvider.getOwner());
		this.fgProvider = fgProvider;

		setPopupMenuData(new MenuData(new String[] { "Edit Fields" }));

		setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Function_Graph_Action_Format"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(Side.LEFT);
		FGController leftController = leftDisplay.getController();
		leftController.showFormatChooser();

		FormatManager leftFormatManager = leftController.getMinimalFormatManager();
		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();
		rightController.updateMinimalFormatManager(leftFormatManager);

		fgProvider.stateChanged();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof FgComparisonContext)) {
			return false;
		}

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(Side.LEFT);
		FGController controller = leftDisplay.getController();
		return controller.hasResults();
	}
}
