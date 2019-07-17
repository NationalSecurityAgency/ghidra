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
package ghidra.app.plugin.core.marker;

import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Plugin to manage marker and navigation panels.
 *  
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Provides the marker display",
	description = "This plugin extends the code browser to include left and right marker"
			+ "components.  The left margin shows marks related to the address being shown at "
			+ "that location.  The right margin shows marks at a position that is relative to "
			+ "an addresses within the overall program (Overview).  This plugin also provides "
			+ "a service that other plugins can use to display markers.  Two types of markers are "
			+ "supported; point markers and area markers.  Area markers are used to indicate a range "
			+ "value such as selection.  Point markers are used to represent individual addresses such "
			+ "as bookmarks.",
	servicesRequired = { CodeViewerService.class, GoToService.class },
	servicesProvided = { MarkerService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class, ProgramClosedPluginEvent.class }
)
//@formatter:on
public class MarkerManagerPlugin extends Plugin {

	private CodeViewerService codeViewerService;
	private MarkerManager markerManager;
	private Program program;

	/**
	 * @param tool
	 */
	public MarkerManagerPlugin(PluginTool tool) {
		super(tool);
		markerManager = new MarkerManager(this);

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_NAVIGATION_MARKERS);
		options.setOptionsHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER,
			GhidraOptions.CATEGORY_BROWSER_NAVIGATION_MARKERS));

		registerServiceProvided(MarkerService.class, markerManager);
	}

	@Override
	protected void dispose() {
		if (codeViewerService != null) {
			codeViewerService.removeMarginProvider(markerManager.getMarginProvider());
			codeViewerService.removeOverviewProvider(markerManager.getOverviewProvider());
		}
		markerManager.dispose();
	}

	@Override
	protected void init() {
		codeViewerService = tool.getService(CodeViewerService.class);
		codeViewerService.addMarginProvider(markerManager.getMarginProvider());
		codeViewerService.addOverviewProvider(markerManager.getOverviewProvider());
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program oldProgram = program;
			program = ev.getActiveProgram();
			if (oldProgram != null) {
				markerManager.setProgram(null);
			}
			if (program != null) {
				markerManager.setProgram(program);
			}
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			markerManager.programClosed(((ProgramClosedPluginEvent) event).getProgram());
		}
	}

}
