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
package ghidra.features.codecompare.decompile;

import java.awt.Component;

import docking.ComponentProvider;
import ghidra.app.context.RestrictedAddressSetContext;
import ghidra.features.base.codecompare.panel.CodeComparisonActionContext;

/**
 * Action context for a dual decompiler panel.
 */
public class DualDecompilerActionContext extends CodeComparisonActionContext
		implements RestrictedAddressSetContext {

	private DecompilerCodeComparisonPanel decompilerComparisonPanel = null;

	/**
	 * Creates an action context for a dual decompiler panel.
	 * @param provider the provider for this context
	 * @param panel the DecompilerComparisonPanel
	 * @param source the source of the action
	 */
	public DualDecompilerActionContext(ComponentProvider provider,
			DecompilerCodeComparisonPanel panel, Component source) {
		super(provider, panel, source);
		this.decompilerComparisonPanel = panel;
	}

	/**
	 * Returns the {@link DecompilerCodeComparisonPanel} that generated this context
	 * @return the decompiler comparison panel that generated this context
	 */
	@Override
	public DecompilerCodeComparisonPanel getCodeComparisonPanel() {
		return decompilerComparisonPanel;
	}
}
