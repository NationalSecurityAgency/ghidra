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
package ghidra.features.codecompare.functiongraph;

import java.awt.Component;

import docking.ComponentProvider;
import ghidra.features.base.codecompare.panel.CodeComparisonActionContext;
import ghidra.features.base.codecompare.panel.CodeComparisonView;

/**
 * Action context for a dual Function Graph panel.
 */
public class FgComparisonContext extends CodeComparisonActionContext {

	private FunctionGraphCodeComparisonView fgProvider;
	private FgDisplay display;
	private boolean isLeft;

	public FgComparisonContext(ComponentProvider provider,
			FunctionGraphCodeComparisonView fgPanel,
			FgDisplay display, Component component, boolean isLeft) {
		super(provider, fgPanel, component);
		this.fgProvider = fgPanel;
		this.display = display;
		this.isLeft = isLeft;
	}

	@Override
	public CodeComparisonView getCodeComparisonView() {
		return fgProvider;
	}

	public FgDisplay getDisplay() {
		return display;
	}

	public boolean isLeft() {
		return isLeft;
	}
}
