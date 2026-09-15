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
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.features.codecompare.functiongraph.*;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * An action to toggle satellite enablement for the Function Graph comparison views.
 */
public class FgToggleSatelliteAction extends ToggleDockingAction {

	private FunctionGraphCodeComparisonView fgProvider;

	public FgToggleSatelliteAction(FunctionGraphCodeComparisonView fgProvider) {
		super("Display Satellite View", fgProvider.getOwner());
		this.fgProvider = fgProvider;

		setPopupMenuData(new MenuData(new String[] { "Display Satellite" }));

		setHelpLocation(new HelpLocation("VisualGraph", "Satellite_View"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(Side.LEFT);

		FGController leftController = leftDisplay.getController();
		boolean visible = isSelected();
		leftController.setSatelliteVisible(visible);

		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();
		rightController.setSatelliteVisible(visible);

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
