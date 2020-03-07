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
package ghidra.app.plugin.core.overview;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.*;
import docking.menu.MultiActionDockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;

/**
 * Plugin to manage {@link OverviewColorService}s.  It creates actions for each service and installs
 * and removes {@link OverviewColorComponent} as indicated by the action.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Overview Color Manager",
	description = "Provides various color mappings for the program address space.",
	servicesRequired = CodeViewerService.class
)
//@formatter:on
public class OverviewColorPlugin extends ProgramPlugin {
	public static final String HELP_TOPIC = "OverviewPlugin";
	private static final String ACTIVE_SERVICES = "ActiveServices";
	private List<OverviewColorService> allServices;
	private Map<OverviewColorService, OverviewColorComponent> activeServices =
		new LinkedHashMap<>(); // maintain the left to right order of the active overview bars.
	private CodeViewerService codeViewerService;
	private Map<OverviewColorService, OverviewToggleAction> actionMap = new HashMap<>();
	private MultiActionDockingAction multiAction;

	public OverviewColorPlugin(PluginTool tool) {
		super(tool, false, false);
	}

	@Override
	protected void init() {
		super.init();
		codeViewerService = tool.getService(CodeViewerService.class);
		allServices = ClassSearcher.getInstances(OverviewColorService.class);
		createActions();
		for (OverviewColorService service : allServices) {
			service.initialize(tool);
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String[] activeServiceNames = saveState.getStrings(ACTIVE_SERVICES, new String[0]);
		for (String serviceName : activeServiceNames) {
			OverviewColorService service = getService(serviceName);
			if (service == null) {
				Msg.warn(this, "Can't restore OverviewColorService: " + serviceName);
				continue;
			}
			OverviewToggleAction action = actionMap.get(service);
			action.setSelected(true);
			// do this later so that they show up to the left of the standard marker service overview.
			SwingUtilities.invokeLater(() -> installOverview(service));
		}
	}

	private OverviewColorService getService(String serviceName) {
		for (OverviewColorService service : allServices) {
			if (service.getName().equals(serviceName)) {
				return service;
			}
		}
		return null;
	}

	@Override
	protected void cleanup() {

		List<OverviewColorService> services = new ArrayList<>(activeServices.keySet());
		for (OverviewColorService service : services) {
			uninstallOverview(service);
		}
		codeViewerService.removeLocalAction(multiAction);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putStrings(ACTIVE_SERVICES, getActiveServiceNames());
	}

	private String[] getActiveServiceNames() {
		List<String> names =
			activeServices.keySet().stream().map(s -> s.getName()).collect(Collectors.toList());

		return names.toArray(new String[names.size()]);
	}

	private void createActions() {
		for (OverviewColorService overviewColorService : allServices) {
			actionMap.put(overviewColorService,
				new OverviewToggleAction(getName(), overviewColorService));
		}
		multiAction = new MultiActionDockingAction("Overview", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				// do nothing - the following setPerformActionOnButtonClick(false) will ensure
				// this never gets called.
			}
		};
		multiAction.setPerformActionOnButtonClick(false);
		multiAction.setActions(new ArrayList<DockingActionIf>(actionMap.values()));
		multiAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/x-office-document-template.png")));
		codeViewerService.addLocalAction(multiAction);
		multiAction.setDescription("Toggles overview margin displays.");
		multiAction.setHelpLocation(
			new HelpLocation(OverviewColorPlugin.HELP_TOPIC, OverviewColorPlugin.HELP_TOPIC));

	}

	private class OverviewToggleAction extends ToggleDockingAction {

		private OverviewColorService service;

		public OverviewToggleAction(String owner, OverviewColorService service) {
			super(service.getName(), owner);
			this.service = service;
			setMenuBarData(new MenuData(new String[] { "Show " + service.getName() }));
			setHelpLocation(service.getHelpLocation());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isSelected()) {
				installOverview(service);
			}
			else {
				uninstallOverview(service);
			}
		}

	}

	/**
	 * Installs the given {@link OverviewColorService} into the Listing margin bars.
	 * This is public only for testing and screenshot purposes.
	 * @param overviewColorService the service to display colors in the Listing's margin bars.
	 */
	public void installOverview(OverviewColorService overviewColorService) {
		overviewColorService.setProgram(currentProgram);
		OverviewColorComponent overview = new OverviewColorComponent(tool, overviewColorService);
		activeServices.put(overviewColorService, overview);
		codeViewerService.addOverviewProvider(overview);
		overview.installActions();
	}

	private void uninstallOverview(OverviewColorService overviewColorService) {
		OverviewColorComponent overviewComponent = activeServices.get(overviewColorService);
		overviewComponent.uninstallActions();
		codeViewerService.removeOverviewProvider(overviewComponent);
		activeServices.remove(overviewColorService);
		overviewColorService.setProgram(null);
	}

	@Override
	protected void programActivated(Program program) {
		for (OverviewColorService service : activeServices.keySet()) {
			service.setProgram(program);
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		for (OverviewColorService service : activeServices.keySet()) {
			service.setProgram(null);
		}
	}
}
