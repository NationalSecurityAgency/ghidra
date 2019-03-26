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
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Show Domain Folder change notifications",
	description = "Displays active project domain folder change notifications",
	servicesRequired = { FrontEndService.class }
)
//@formatter:on
public class DomainFolderChangesDisplayPlugin extends Plugin
		implements FrontEndOnly, ProjectListener, DomainFolderChangeListener {

	private DomainFolderChangesDisplayComponentProvider provider;

	public DomainFolderChangesDisplayPlugin(PluginTool tool) {

		super(tool);
		provider = new DomainFolderChangesDisplayComponentProvider(tool, getName());
	}

	@Override
	protected void init() {

		Project activeProject = tool.getProjectManager().getActiveProject();
		if (activeProject != null) {
			projectOpened(activeProject);
		}

		FrontEndService frontEnd = tool.getService(FrontEndService.class);
		frontEnd.addProjectListener(this);
		super.init();
	}

	@Override
	protected void dispose() {
		FrontEndService frontEnd = tool.getService(FrontEndService.class);
		frontEnd.addProjectListener(this);

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
	public void domainFolderRemoved(DomainFolder parent, String name) {
		provider.addText("domainFolderRemoved: parent=" + parent.getPathname() + ", name=" + name);
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		provider.addText("domainFileRemoved: parent=" + parent.getPathname() + ", name=" + name +
			", fileID=" + fileID);
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
	public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
		provider.addText("domainFileObjectReplaced: " + file.getPathname());
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
