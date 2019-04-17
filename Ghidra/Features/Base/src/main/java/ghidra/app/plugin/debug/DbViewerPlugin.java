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

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import resources.Icons;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Show database tables",
	description = "This plugin is a debug aid that allows the user to browse database tables.",
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class DbViewerPlugin extends Plugin {

	private DbViewerProvider viewer;
	private DockingAction refreshAction;

	public DbViewerPlugin(PluginTool tool) {
		super(tool);

		setupActions();
	}

	@Override
	protected void dispose() {
		if (viewer != null) {
			deactivateViewer();
			tool.removeComponentProvider(viewer);
			viewer.dispose();
			viewer = null;
		}
		super.dispose();
	}

	private void setupActions() {

		refreshAction = new DockingAction("Refresh", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (viewer != null) {
					viewer.refresh();
				}
			}
		};

		refreshAction.setEnabled(false);
		ImageIcon icon = Icons.REFRESH_ICON;
		refreshAction.setToolBarData(new ToolBarData(icon));
	}

	private void activateViewer(DomainObjectAdapterDB dobj) {
		if (viewer == null) {
			viewer = new DbViewerProvider(this);
			tool.addComponentProvider(viewer, false);
			tool.addLocalAction(viewer, refreshAction);
		}
		viewer.openDatabase(dobj.getName(), dobj.getDBHandle());
		refreshAction.setEnabled(true);
	}

	private void deactivateViewer() {
		if (viewer != null) {
			refreshAction.setEnabled(false);
			viewer.closeDatabase();
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			deactivateViewer();
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program currentProgram = ev.getActiveProgram();
			if (currentProgram instanceof DomainObjectAdapterDB) {
				activateViewer((DomainObjectAdapterDB) currentProgram);
			}
		}
	}

}
