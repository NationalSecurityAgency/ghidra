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
package ghidra.framework.main.projectdata.actions;

import java.awt.Component;
import java.awt.event.KeyEvent;
import java.io.IOException;

import javax.swing.Icon;

import docking.action.*;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.model.ProjectData;
import ghidra.util.HelpLocation;
import ghidra.util.task.*;
import resources.Icons;

public class ProjectDataRefreshAction extends FrontendProjectTreeAction {

	private static Icon icon = Icons.REFRESH_ICON;

	public ProjectDataRefreshAction(String owner, String group) {
		super("Refresh", owner);
		setPopupMenuData(new MenuData(new String[] { "Refresh" }, icon, group));
		setDescription("Refresh folders and files");
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F5, 0));
		setToolBarData(new ToolBarData(icon, group));
		setHelpLocation(new HelpLocation(owner, "RefreshFolders"));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		refresh(context.getProjectData(), context.getComponent());
	}

	public void refresh(ProjectData projectData, Component comp) {
		TaskLauncher.launch(new Task("Refresh folders and files", false, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					projectData.refresh(false);
				}
				catch (IOException e) {
					ClientUtil.handleException(projectData.getRepository(), e,
						"Refresh Project Data", false, comp);
				}
			}
		});
	}
}
