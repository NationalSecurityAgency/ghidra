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

import java.util.List;

import javax.swing.Icon;

import docking.action.MenuData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;

public class ProjectDataOpenToolAction extends FrontendProjectTreeAction {
	private String toolName;

	public ProjectDataOpenToolAction(String owner, String group, String toolName, Icon icon) {
		super("Open" + toolName, owner);
		this.toolName = toolName;
		String[] menuPath = { "Open With", HTMLUtilities.escapeHTML(toolName) };
		setPopupMenuData(new MenuData(menuPath, icon, "Open"));
		setHelpLocation(new HelpLocation(owner, "Open_File_With"));

	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		List<DomainFile> selectedFiles = context.getSelectedFiles();
		openInTool(selectedFiles);
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		return context.getSelectedFiles().size() > 0 && context.getSelectedFolders().size() == 0;
	}

	private void openInTool(List<DomainFile> fileList) {

		Project project = AppInfo.getActiveProject();
		ToolChest toolChest = project.getLocalToolChest();
		ToolManager toolManager = project.getToolManager();
		Workspace activeWorkspace = toolManager.getActiveWorkspace();

		ToolTemplate template = toolChest.getToolTemplate(toolName);
		PluginTool newTool = activeWorkspace.runTool(template);

		DomainFile[] files = fileList.toArray(new DomainFile[fileList.size()]);
		newTool.acceptDomainFiles(files);
	}
}
