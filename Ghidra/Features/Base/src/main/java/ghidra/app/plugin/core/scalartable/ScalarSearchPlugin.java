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
package ghidra.app.plugin.core.scalartable;

import java.util.*;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.events.ViewChangedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.HelpLocation;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.task.SwingUpdateManager;

/**
 * Allows users to search for scalar values within a program.
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays scalars",
	description = "This plugin allows users to search for scalar values in a program.",
	servicesRequired = { GoToService.class },
	eventsConsumed = { ViewChangedPluginEvent.class }
)
//@formatter:on
public class ScalarSearchPlugin extends ProgramPlugin implements DomainObjectListener {

	final static String SEARCH_ACTION_NAME = "Search for Scalars";

	private SwingUpdateManager reloadUpdateMgr;
	private DockingAction searchAction;
	private Set<ScalarSearchProvider> providers = new HashSet<>();

	public ScalarSearchPlugin(PluginTool tool) {
		super(tool, true, true);

		reloadUpdateMgr =
			new SwingUpdateManager(1000, 60000, () -> providers.forEach(p -> p.reload()));
	}

	@Override
	public void init() {
		super.init();
		createActions();
	}

	@Override
	public void dispose() {
		reloadUpdateMgr.dispose();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}

		Iterator<ScalarSearchProvider> iter = providers.iterator();
		while (iter.hasNext()) {
			ScalarSearchProvider provider = iter.next();
			provider.dispose();
			iter.remove();
		}

		super.dispose();
	}

	/**
	 * We need to be aware of changes to the program that could result in scalars being
	 * added/removed. When this happens we want to update the appropriate providers.
	 *
	 * @param ev the domain change event
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_REMOVED)) {
			reloadUpdateMgr.update();
		}
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programClosed(Program program) {
		program.removeListener(this);

		// Find any providers showing scalars for the closed program and
		// eliminate them.
		Iterator<ScalarSearchProvider> iter = providers.iterator();
		while (iter.hasNext()) {
			ScalarSearchProvider provider = iter.next();
			if (provider.getProgram() == program) {
				provider.programClosed(program);
				iter.remove();
			}
		}
	}

	private void openSearchDialog() {

		ScalarSearchDialog dialog = new ScalarSearchDialog(this);
		dialog.show();

		ScalarSearchProvider provider = dialog.getProvider();
		if (provider != null) {
			providers.add(provider);
		}
	}

	private void createActions() {

		searchAction = new NavigatableContextAction(SEARCH_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				openSearchDialog();
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return !(context instanceof RestrictedAddressSetContext);
			}
		};

		searchAction.setHelpLocation(new HelpLocation(this.getName(), "Scalar_Search"));
		searchAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SEARCH, "For Scalars..." }, null, "search for"));
		searchAction.setDescription("Search program for scalars");
		searchAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(searchAction);

		//
		// Unusual Code: This plugin does not use the delete action directly, but our transient
		//               tables do. We need a way to have keybindings shared for this action.
		//               Further, we need to register it now, not when the transient
		//               providers are created, as they would only appear in the options at
		//               that point.
		//
		DeleteTableRowAction.registerDummy(tool, getName());
	}
}
