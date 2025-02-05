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
package ghidra.app.plugin.debug;

import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.DIAGNOSTIC,
	shortDescription = "Show Domain Folder change notifications",
	description = "Displays active project domain folder change notifications",
	servicesRequired = { FrontEndService.class }
)
//@formatter:on
public class DomainFolderChangesDisplayPlugin extends Plugin
		implements ApplicationLevelOnlyPlugin, ProjectListener, DomainFolderChangeListener {

	private DomainFolderChangesDisplayComponentProvider provider;

	public DomainFolderChangesDisplayPlugin(PluginTool tool) {

		super(tool);
		provider = new DomainFolderChangesDisplayComponentProvider(tool, getName());
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == FrontEndService.class) {
			((FrontEndService) service).removeProjectListener(this);
		}
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == FrontEndService.class) {
			((FrontEndService) service).addProjectListener(this);
		}
	}

	@Override
	protected void init() {

		Project activeProject = tool.getProjectManager().getActiveProject();
		if (activeProject != null) {
			projectOpened(activeProject);
		}

		super.init();
	}

	@Override
	protected void dispose() {

		// Normal shutdown will have removed the FrontEndService at the point dispose() is called.
		// In this case, the listener is removed in a call to serviceRemoved().  If this plugin is 
		// removed by the user, then dispose() is called and we need to remove the listener.
		FrontEndService frontEnd = tool.getService(FrontEndService.class);
		if (frontEnd != null) {
			frontEnd.removeProjectListener(this);
		}

		Project activeProject = tool.getProjectManager().getActiveProject();
		if (activeProject != null) {
			projectClosed(activeProject);
		}
	}

	@Override
	public void projectOpened(Project project) {
		project.getProjectData().addDomainFolderChangeListener(this);
	}

	@Override
	public void projectClosed(Project project) {
		project.getProjectData().removeDomainFolderChangeListener(this);
	}

	@Override
	public void domainFolderAdded(DomainFolder folder) {
		provider.addText("domainFolderAdded: " + folder.getPathname());
	}

	@Override
	public void domainFileAdded(DomainFile file) {
		provider.addText("domainFileAdded: " + file.getPathname());
	}

	@Override
	public void domainFolderRemoved(DomainFolder parent, String folderName) {
		provider.addText(
			"domainFolderRemoved: parent=" + parent.getPathname() + ", name=" + folderName);
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String folderName, String fileID) {
		provider.addText("domainFileRemoved: parent=" + parent.getPathname() + ", name=" +
			folderName + ", fileID=" + fileID);
	}

	@Override
	public void domainFolderRenamed(DomainFolder folder, String oldName) {
		provider.addText("domainFolderRenamed: " + folder.getPathname() + ", oldName=" + oldName);
	}

	@Override
	public void domainFileRenamed(DomainFile file, String oldName) {
		provider.addText("domainFileRenamed: " + file.getPathname() + ", oldName=" + oldName);
	}

	@Override
	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
		provider.addText("domainFolderMoved: " + folder.getPathname() + ", oldParent=" +
			oldParent.getPathname());
	}

	@Override
	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
		provider.addText("domainFileMoved: " + file.getPathname() + ", oldParent=" +
			oldParent.getPathname() + ", oldName=" + oldName);
	}

	@Override
	public void domainFolderSetActive(DomainFolder folder) {
		provider.addText("domainFolderSetActive: " + folder.getPathname());
	}

	@Override
	public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
		provider.addText("domainFileStatusChanged: " + file.getPathname() + ", fileIDset=" +
			Boolean.toString(fileIDset));
	}

	@Override
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		provider.addText("domainFileObjectOpenedForUpdate: " + file.getPathname());
	}

	@Override
	public void domainFileObjectClosed(DomainFile file, DomainObject object) {
		provider.addText("domainFileObjectClosed: " + file.getPathname());
	}
}
