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

import docking.tool.ToolConstants;
import generic.theme.GIcon;
import ghidra.framework.client.RemoteAdapterListener;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import resources.MultiIcon;

public class DomainFolderRootNode extends DomainFolderNode implements RemoteAdapterListener {

	private static final Icon CLOSED_PROJECT = new GIcon("icon.datatree.node.domain.folder.closed");
	private static final Icon OPEN_PROJECT = new GIcon("icon.datatree.node.domain.folder.open");

	private static final Icon CONNECTED_OVERLAY =
		new GIcon("icon.project.root.repo.connected.overlay");
	private static final Icon DISCONNECTED_OVERLAY =
		new GIcon("icon.project.root.repo.disconnected.overlay");

	private static enum Status {
		OPEN(true),
		CLOSED(false),
		OPEN_CONNECTED(true, true),
		CLOSED_CONNECTED(false, true),
		OPEN_DISCONNECTED(true, false),
		CLOSED_DISCONNECTED(false, false);

		final Icon icon;

		private Status(boolean isOpen) {
			icon = isOpen ? OPEN_PROJECT : CLOSED_PROJECT;
		}

		private Status(boolean isOpen, boolean isConnected) {
			MultiIcon multiIcon = new MultiIcon(isOpen ? OPEN_PROJECT : CLOSED_PROJECT);
			multiIcon.addIcon(isConnected ? CONNECTED_OVERLAY : DISCONNECTED_OVERLAY);
			icon = multiIcon;
		}

		static Status getStatus(boolean isOpen, RepositoryAdapter repository) {
			if (isOpen) {
				if (repository == null) {
					return OPEN;
				}
				return repository.isConnected() ? OPEN_CONNECTED : OPEN_DISCONNECTED;
			}
			if (repository == null) {
				return CLOSED;
			}
			return repository.isConnected() ? CLOSED_CONNECTED : CLOSED_DISCONNECTED;
		}
	}

	private String projectName;
	private RepositoryAdapter repository;

	private Status status;
	private String toolTipText;

	DomainFolderRootNode(String projectName, DomainFolder rootFolder, ProjectData projectData,
			DomainFileFilter filter) {
		super(rootFolder, filter);
		this.projectName = projectName;
		this.repository = getProjectData().getRepository();
		if (repository != null) {
			repository.addListener(this);
		}

		toolTipText = getToolTip(projectData);
	}

	@Override
	public void dispose() {
		if (repository != null) {
			repository.removeListener(this);
		}
		super.dispose();
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
		fireNodeChanged();
	}

	@Override
	public String getToolTip() {
		return toolTipText;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		status = Status.getStatus(expanded, repository);
		return status.icon;
	}

	private String getToolTip(ProjectData projectData) {
		ProjectLocator projectLocator = projectData.getProjectLocator();
		File dir = projectLocator.getProjectDir();
		String toolTip = dir.getAbsolutePath();
		if (!projectLocator.isTransient() && repository != null) {
			ServerInfo info = repository.getServerInfo();
			String serverName = info.getServerName() + ":";
			String statusText = repository.isConnected() ? "connected" : "disconnected";
			toolTip += " [" + serverName + repository.getName() + ", " + statusText + "]";
		}
		return toolTip;
	}

	@Override
	public void connectionStateChanged(Object adapter) {
		toolTipText = getToolTip(getProjectData());
	}
}
