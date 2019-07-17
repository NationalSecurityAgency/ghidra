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

import ghidra.framework.plugintool.PluginTool;

/**
 * Panel that displays two decompilers for comparison and synchronizes their scrolling 
 * using a basic coordinator.
 */
public class BasicDecompilerCodeComparisonPanel
		extends DecompilerCodeComparisonPanel<BasicDecompilerFieldPanelCoordinator> {

	/**
	 * Creates a default comparison panel with two decompilers.
	 * @param owner the owner of this panel
	 * @param tool the tool displaying this panel
	 */
	public BasicDecompilerCodeComparisonPanel(String owner, PluginTool tool) {
		super(owner, tool);
	}

	@Override
	public Class<? extends DecompilerCodeComparisonPanel<BasicDecompilerFieldPanelCoordinator>> getPanelThisSupersedes() {
		return null; // Doesn't supersede any other panel.
	}

	@Override
	protected BasicDecompilerFieldPanelCoordinator createFieldPanelCoordinator() {
		return new BasicDecompilerFieldPanelCoordinator(this, isScrollingSynced());
	}
}
