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

import javax.swing.Icon;

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

	private DbViewerProvider provider;
	private DockingAction refreshAction;

	public DbViewerPlugin(PluginTool tool) {
		super(tool);

		setupActions();
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			deactivateViewer();
			tool.removeComponentProvider(provider);
			provider.dispose();
			provider = null;
		}
		super.dispose();
	}

	private void setupActions() {

		refreshAction = new DockingAction("Refresh", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (provider != null) {
					provider.refresh();
				}
			}
		};

		refreshAction.setEnabled(false);
		Icon icon = Icons.REFRESH_ICON;
		refreshAction.setToolBarData(new ToolBarData(icon));
	}

	private void activateViewer(DomainObjectAdapterDB dobj) {
		if (provider == null) {
			provider = new DbViewerProvider(this);
			tool.addComponentProvider(provider, false);
			tool.addLocalAction(provider, refreshAction);
		}
		provider.openDatabase(dobj.getName(), dobj.getDBHandle());
		refreshAction.setEnabled(true);
	}

	private void deactivateViewer() {
		if (provider != null) {
			refreshAction.setEnabled(false);
			provider.closeDatabase();
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
