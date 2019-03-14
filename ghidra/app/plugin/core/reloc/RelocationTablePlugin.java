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
package ghidra.app.plugin.core.reloc;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.SelectionNavigationAction;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays relocation information",
	description = "This plugin provides a component for displaying the reloction table. "
			+ "The table can be used to navigate in the code browser.",
	servicesRequired = { GoToService.class },
	eventsProduced = { ProgramLocationPluginEvent.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class RelocationTablePlugin extends Plugin implements DomainObjectListener {

	private Program currentProgram;
	private GoToService goToService;
	private RelocationProvider provider;

	public RelocationTablePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
		provider = new RelocationProvider(this);

		createActions();
	}

	private void createActions() {
		DockingAction programSelectionAction =
			new DockingAction("Make Selection", getName(), false) {
				@Override
				public void actionPerformed(ActionContext context) {
					makeSelection();
				}
			};
		programSelectionAction.setDescription("Make a selection using selected rows");
		ImageIcon icon = ResourceManager.loadImage("images/text_align_justify.png");
		programSelectionAction.setToolBarData(new ToolBarData(icon));
		programSelectionAction.setPopupMenuData(
			new MenuData(new String[] { "Make Selection" }, icon));
		programSelectionAction.setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, "Make_Selection"));
		tool.addLocalAction(provider, programSelectionAction);

		DockingAction navigationAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, navigationAction);
	}

	private void makeSelection() {
		ProgramSelection selection = provider.getTable().getProgramSelection();
		PluginEvent event = new ProgramSelectionPluginEvent(getName(), selection, currentProgram);
		firePluginEvent(event);
	}

	@Override
	public void dispose() {
		super.dispose();
		provider.dispose();
		currentProgram = null;
		goToService = null;
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program oldProg = currentProgram;
			Program newProg = ev.getActiveProgram();
			if (oldProg != null) {
				programClosed();
			}
			if (newProg != null) {
				programOpened(newProg);
			}
		}
	}

	private void programOpened(Program p) {
		p.addListener(this);
		currentProgram = p;
		provider.setProgram(p);
	}

	private void programClosed() {
		currentProgram.removeListener(this);
		currentProgram = null;
		provider.setProgram(null);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(ChangeManager.DOCR_IMAGE_BASE_CHANGED) ||
			ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			provider.setProgram(currentProgram);
		}

	}

}
