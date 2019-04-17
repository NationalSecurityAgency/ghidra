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

import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.action.DockingActionProviderIf;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.util.HelpLocation;

public class VersionHistoryDialog extends DialogComponentProvider
		implements ProjectListener, DockingActionProviderIf {

	private VersionHistoryPanel versionPanel;
	private MyFolderListener listener = new MyFolderListener();

	public VersionHistoryDialog() {

		super("Version History", false);
		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		setHelpLocation(new HelpLocation(GenericHelpTopics.REPOSITORY, "Show_History"));
		versionPanel = new VersionHistoryPanel(frontEndTool, null, true);
		addWorkPanel(versionPanel);
		addDismissButton();
		versionPanel.addPopupActions(this);
	}

	public void setDomainFile(DomainFile df) {

		versionPanel.setDomainFile(df);

		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		frontEndTool.addProjectListener(this);
		Project project = frontEndTool.getProject();
		if (project != null && df != null) {
			setTitle("Version History for " + df.getName());
			project.getProjectData().addDomainFolderChangeListener(listener);
		}
		else {
			setTitle("Version History");
			project.getProjectData().removeDomainFolderChangeListener(listener);
		}
	}

	@Override
	protected void dismissCallback() {

		close();

		setDomainFile(null);
	}

	@Override
	public void projectClosed(Project project) {
		dismissCallback();
	}

	@Override
	public void projectOpened(Project project) {
		// ignore
	}

	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void stateChanged(String affectedNewPath, String affectedOldPath, boolean isFolder) {
			String path = versionPanel.getDomainFilePath();
			if (path == null || affectedOldPath == null) {
				return;
			}
			if (isFolder) {
				affectedOldPath += FileSystem.SEPARATOR;
				if (path.startsWith(affectedOldPath) && !versionPanel.getDomainFile().exists()) {
					dismissCallback();
				}
			}
			else if (affectedOldPath.equals(path)) {
				if (affectedNewPath == null) {
					dismissCallback();
				}
				else {
					versionPanel.refresh();
				}
			}
		}

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			if (file.equals(versionPanel.getDomainFile())) {
				versionPanel.refresh();
			}
		}

		@Override
		public void domainFileRemoved(DomainFolder parentFolder, String name, String fileID) {
			DomainFile domainFile = versionPanel.getDomainFile();
			if (parentFolder.equals(domainFile.getParent()) && domainFile.getName().equals(name)) {
				// must be done later otherwise concurrent mod exception occurs
				// in the domain folder notification of listeners.
				SwingUtilities.invokeLater(() -> dismissCallback());
			}
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContext actionContext = new ActionContext(null, this, this);
		actionContext.setMouseEvent(event);
		return actionContext;
	}

	@Override
	public List<DockingActionIf> getDockingActions(ActionContext context) {
		return versionPanel.getDockingActions(context);
	}
}
