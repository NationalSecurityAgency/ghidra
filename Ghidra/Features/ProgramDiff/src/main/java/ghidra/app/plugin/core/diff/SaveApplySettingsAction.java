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
package ghidra.app.plugin.core.diff;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Action to save the current Diff Apply Settings as the new defaults to be used when new Diffs are started.
 */
class SaveApplySettingsAction extends DockingAction {

	private final static String ACTION_NAME = "Save Default Diff Apply Settings";
	private final static String GROUP_NAME = "DEFAULTS";
	private final static String DESCRIPTION = "Save Current Diff Apply Settings As The Default.";
	private DiffApplySettingsProvider settingsProvider;
	private DiffApplySettingsOptionManager settingsOptionMgr;

	/**
	 * Creates a new SaveApplySettingsAction.
	 * @param settingsProvider the component provider where this action will be added.
	 * @param settingsOptionMgr the options manager to save the default apply settings to.
	 */
	SaveApplySettingsAction(DiffApplySettingsProvider settingsProvider,
			DiffApplySettingsOptionManager settingsOptionMgr) {
		super(ACTION_NAME, settingsProvider.getPlugin().getName());
		this.settingsProvider = settingsProvider;
		this.settingsOptionMgr = settingsOptionMgr;
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/disk.png"), GROUP_NAME));
		setEnabled(true);
		setDescription(DESCRIPTION);
		setHelpLocation(new HelpLocation(HelpTopics.DIFF, ACTION_NAME));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		JComponent applySettingsComponent = settingsProvider.getComponent();
		return contextObject == applySettingsComponent;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		settingsOptionMgr.saveDefaultApplyFilter(settingsProvider.getApplyFilter());
		settingsProvider.getPlugin().getTool().setStatusInfo(
			"Diff Apply Settings have been saved to the tool as the new defaults.");
	}

}
