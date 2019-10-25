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
package ghidra.framework.main.datatree;

import java.io.File;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.tool.ToolConstants;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import resources.ResourceManager;

public class DomainFolderRootNode extends DomainFolderNode {
	private static final ImageIcon CLOSED_PROJECT =
		ResourceManager.loadImage("images/closedSmallFolder.png");
	private static final ImageIcon OPEN_PROJECT =
		ResourceManager.loadImage("images/openSmallFolder.png");

	private String projectName;
	private String toolTipText;

	DomainFolderRootNode(String projectName, DomainFolder rootFolder, ProjectData projectData,
			DomainFileFilter filter) {
		super(rootFolder, filter);
		this.projectName = projectName;
		toolTipText = getToolTip(projectData);
	}

	@Override
	public String getName() {
		if (projectName == null) {
			return ToolConstants.NO_ACTIVE_PROJECT;
		}
		return projectName;
	}

	void setName(String newName) {
		projectName = newName;
		fireNodeChanged(null, this);
	}

	@Override
	public String getToolTip() {
		return toolTipText;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_PROJECT : CLOSED_PROJECT;
	}

	private String getToolTip(ProjectData projectData) {
		RepositoryAdapter repository = projectData.getRepository();
		File dir = projectData.getProjectLocator().getProjectDir();
		String toolTip = dir.getAbsolutePath();
		if (!getDomainFolder().isInWritableProject() && repository != null) {
			ServerInfo info = repository.getServerInfo();
			String serverName = "";
			if (info != null) {
				serverName = info.getServerName() + ", ";
			}
			toolTip += " [" + serverName + repository.getName() + "]";
		}
		return toolTip;
	}
}
