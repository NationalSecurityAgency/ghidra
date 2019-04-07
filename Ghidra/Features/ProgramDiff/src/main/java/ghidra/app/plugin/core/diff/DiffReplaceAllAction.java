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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.program.util.ProgramMergeFilter;

public class DiffReplaceAllAction extends DockingAction {
	
	private final static String ACTION_NAME = "Set Replace for All Apply Settings";
	private final static String GROUP_NAME = "DIFF_APPLY_ACTION";
	private final static String DESCRIPTION = "Change all the difference type apply settings to Replace.";
	private static String[] popupPath = new String[] { ACTION_NAME };
	private static String[] menuPath = new String[] { ACTION_NAME };
	private DiffApplySettingsProvider provider;

	/**
	 * @param provider the provider using this action
	 */
	public DiffReplaceAllAction(DiffApplySettingsProvider provider) {
		super("Set All To Replace", provider.getPlugin().getName());
		this.provider = provider;
		setMenuBarData( new MenuData( menuPath, GROUP_NAME ) );
		setPopupMenuData( new MenuData( popupPath, GROUP_NAME ) );		
		setDescription(DESCRIPTION);
	}

	@Override
    public void actionPerformed(ActionContext context) {
		provider.setApplyFilter(new ProgramMergeFilter(ProgramMergeFilter.ALL, ProgramMergeFilter.REPLACE));
	}

}
