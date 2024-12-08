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
import java.io.FileNotFoundException;
import java.util.Collections;
import java.util.List;

import docking.*;
import docking.action.DockingActionIf;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.util.HelpLocation;

public class VersionHistoryDialog extends DialogComponentProvider implements ProjectListener {

	private VersionHistoryPanel versionPanel;
	private MyFolderListener listener;
	private List<DockingActionIf> popupActions = Collections.emptyList();

	public VersionHistoryDialog(DomainFile domainFile) {

		super("Version History", false);
		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		setHelpLocation(new HelpLocation(GenericHelpTopics.VERSION_CONTROL, "Show_History"));
		versionPanel = new VersionHistoryPanel(frontEndTool, null, true);
		addWorkPanel(versionPanel);
		addDismissButton();

		setDomainFile(domainFile);
		popupActions = versionPanel.createPopupActions();
	}

	private void setDomainFile(DomainFile df) {

		versionPanel.setDomainFile(df);

		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		frontEndTool.addProjectListener(this);
		Project project = frontEndTool.getProject();
		if (project != null && df != null) {
			setTitle("Version History for " + df.getName());
			listener = new MyFolderListener();
			project.getProjectData().addDomainFolderChangeListener(listener);
		}
	}

	@Override
	protected void dialogShown() {
		super.dialogShown();

		for (DockingActionIf action : popupActions) {
			addAction(action);
		}
	}

	@Override
	protected void dialogClosed() {
		super.dialogClosed();

		for (DockingActionIf action : popupActions) {
			removeAction(action);
		}

		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		frontEndTool.removeProjectListener(this);
		if (listener != null) {
			Project project = frontEndTool.getProject();
			if (project != null) {
				project.getProjectData().removeDomainFolderChangeListener(listener);
			}
			listener = null;
		}
	}

	@Override
	public void projectClosed(Project project) {
		close();
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
					close();
				}
			}
			else if (affectedOldPath.equals(path)) {
				close();
			}
		}

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			if (file.equals(versionPanel.getDomainFile())) {
				try {
					versionPanel.refresh();
				}
				catch (FileNotFoundException e) {
					close();
				}
			}
		}

		@Override
		public void domainFileRemoved(DomainFolder parentFolder, String name, String fileID) {
			DomainFile domainFile = versionPanel.getDomainFile();
			if (domainFile != null && parentFolder.equals(domainFile.getParent()) &&
				domainFile.getName().equals(name)) {
				close();
			}
		}

	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContext actionContext = new DefaultActionContext(null, this, versionPanel.getTable());
		actionContext.setMouseEvent(event);
		return actionContext;
	}
}
