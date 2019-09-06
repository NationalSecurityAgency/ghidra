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
package ghidra.app.decompiler.component;

import java.awt.Component;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.context.RestrictedAddressSetContext;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanelActionContext;

/**
 * Action context for a dual decompiler panel.
 */
public class DualDecompilerActionContext extends ActionContext
		implements RestrictedAddressSetContext, CodeComparisonPanelActionContext {

	private CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel = null;

	/**
	 * Creates an action context for a dual decompiler panel.
	 * @param provider the provider for this context
	 * @param cPanel the decompiler panel associated with this context
	 * @param source the source of the action
	 */
	public DualDecompilerActionContext(ComponentProvider provider, CDisplayPanel cPanel,
			Component source) {
		super(provider, cPanel, source);
	}

	/**
	 * Sets the CodeComparisonPanel associated with this context.
	 * @param codeComparisonPanel the code comparison panel.
	 */
	public void setCodeComparisonPanel(
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel) {
		this.codeComparisonPanel = codeComparisonPanel;
	}

	@Override
	public CodeComparisonPanel<? extends FieldPanelCoordinator> getCodeComparisonPanel() {
		return codeComparisonPanel;
	}
}
