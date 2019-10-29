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
package ghidra.app.plugin.core.checksums;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Compute Checksums",
	description = ComputeChecksumsPlugin.DESCRIPTION
)
//@formatter:on
public class ComputeChecksumsPlugin extends ProgramPlugin {

	static final String DESCRIPTION = "Computes a variety of checksums algorithms on a file.";

	private ComputeChecksumsProvider provider;

	private DockingAction action;

	/**
	 * Constructor for the ComputeChecksumsPlugin.
	 * @param tool
	 */
	public ComputeChecksumsPlugin(PluginTool tool) {
		super(tool, true, true);
		createActions();

		provider = new ComputeChecksumsProvider(this);
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}

	Program getProgram() {
		return currentProgram;
	}

	private void createActions() {
		action = new DockingAction("GenerateChecksum", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				openProvider();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}
		};
		action.setEnabled(true);
		action.setHelpLocation(
			new HelpLocation("ComputeChecksumsPlugin", "Generate_Checksum_Help"));
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, "Generate Checksum..." }));
		action.setDescription(DESCRIPTION);
		tool.addAction(action);
	}

	private void openProvider() {
		if (provider.isVisible()) {
			provider.toFront();
		}
		else {
			provider.setVisible(true);
		}
		provider.setSelection(currentSelection != null && !currentSelection.isEmpty());
	}

	DockingAction getAction() {
		return action;
	}

	/**
	 * Notifies the provider that the selection has changed.
	 * @param selection the current program selection.
	 */
	@Override
	protected void selectionChanged(ProgramSelection selection) {
		provider.setSelection(hasSelection());
	}

	/**
	 * Returns the current program selection
	 * @return the current program selection
	 */
	ProgramSelection getSelection() {
		return currentSelection;
	}

	/**
	 * Returns true if the current program has a selection
	 * @return true if the current program has a selection
	 */
	boolean hasSelection() {
		ProgramSelection selection = getSelection();
		return selection != null && !selection.isEmpty();
	}

}
