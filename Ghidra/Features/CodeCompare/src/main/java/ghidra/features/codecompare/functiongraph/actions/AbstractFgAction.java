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
import ghidra.features.codecompare.functiongraph.FgComparisonContext;
import ghidra.features.codecompare.functiongraph.FgDisplay;

public abstract class AbstractFgAction extends DockingAction {

	private FgDisplay display;

	protected AbstractFgAction(FgDisplay display, String name) {
		super(name, display.getOwner());
		this.display = display;
	}

	protected boolean isMyDisplay(ActionContext context) {
		if (!(context instanceof FgComparisonContext fgContext)) {
			return false;
		}
		return fgContext.getDisplay() == display;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return isMyDisplay(context);
	}
}
