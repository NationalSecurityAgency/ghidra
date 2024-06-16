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
package ghidra.features.base.codecompare.panel;

import java.awt.Component;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Duo.Side;

public abstract class CodeComparisonActionContext extends DefaultActionContext
		implements CodeComparisonPanelActionContext {
	private CodeComparisonPanel comparisonPanel;

	/** 
	 * Constructor
	 * @param provider the ComponentProvider containing the code comparison panel
	 * @param panel the CodeComparisonPanel that generated this context
	 * @param component the focusable component for associated with the comparison panel
	 */
	public CodeComparisonActionContext(ComponentProvider provider, CodeComparisonPanel panel,
			Component component) {
		super(provider, panel, component);
		this.comparisonPanel = panel;
	}

	/**
	 * Returns the function that is the source of the info being applied. This will be whichever
	 * side of the function diff window that isn't active. 
	 * @return the function to get information from
	 */
	public Function getSourceFunction() {
		Side activeSide = comparisonPanel.getActiveSide();
		return comparisonPanel.getFunction(activeSide.otherSide());
	}

	/**
	 * Returns the function that is the target of the info being applied. This will be whichever
	 * side of the function diff window that is active.
	 * @return the function to apply information to
	 */
	public Function getTargetFunction() {
		Side activeSide = comparisonPanel.getActiveSide();
		return comparisonPanel.getFunction(activeSide);
	}
}
