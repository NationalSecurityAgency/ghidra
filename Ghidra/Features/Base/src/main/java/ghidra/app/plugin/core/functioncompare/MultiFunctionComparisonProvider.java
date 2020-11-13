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
package ghidra.app.plugin.core.functioncompare;

import docking.action.DockingAction;
import ghidra.app.plugin.core.functioncompare.actions.*;
import ghidra.framework.plugintool.Plugin;

/**
 * Provider for a {@link MultiFunctionComparisonPanel}. This differs from the
 * base comparison provider in that it has additional actions that are 
 * appropriate for managing multiple comparisons (add, remove, etc...).
 */
public class MultiFunctionComparisonProvider extends FunctionComparisonProvider {

	/**
	 * Constructor
	 * 
	 * @param plugin the parent plugin
	 */
	public MultiFunctionComparisonProvider(Plugin plugin) {
		super(plugin, "functioncomparisonprovider", plugin.getName());
	}

	@Override
	public FunctionComparisonPanel getComponent() {
		if (functionComparisonPanel == null) {
			functionComparisonPanel = new MultiFunctionComparisonPanel(this, tool);
		}
		return functionComparisonPanel;
	}

	@Override
	boolean isEmpty() {
		return model.getSourceFunctions().isEmpty();
	}

	@Override
	protected void initFunctionComparisonPanel() {
		super.initFunctionComparisonPanel();

		DockingAction nextFunctionAction = new NextFunctionAction(this);
		DockingAction previousFunctionAction = new PreviousFunctionAction(this);
		DockingAction removeFunctionsAction = new RemoveFunctionsAction(this);
		DockingAction openFunctionTableAction = getOpenFunctionTableAction();
		DockingAction navigateToAction = new NavigateToFunctionAction(this);

		addLocalAction(nextFunctionAction);
		addLocalAction(previousFunctionAction);
		addLocalAction(removeFunctionsAction);
		addLocalAction(openFunctionTableAction);
		addLocalAction(navigateToAction);
	}

	/**
	 * Returns an action that opens a table from which users may select
	 * functions for comparison. By default this returns an action that will
	 * open a standard function table, but may be overridden as-needed.
	 *  
	 * @return the docking action
	 */
	protected DockingAction getOpenFunctionTableAction() {
		return new OpenFunctionTableAction(tool, this);
	}
}
