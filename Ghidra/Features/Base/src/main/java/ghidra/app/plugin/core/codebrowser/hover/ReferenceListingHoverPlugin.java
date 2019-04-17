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
package ghidra.app.plugin.core.codebrowser.hover;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeFormatService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A plugin to show tool tip text for hovering over references in the listing.
 *
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Reference Hover",
	description = "Pop-up display of \"referred to\" code in the Code Browser.",
	servicesProvided = { ListingHoverService.class },
	servicesRequired = { CodeFormatService.class },
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class ReferenceListingHoverPlugin extends Plugin {

	private ReferenceListingHover referenceHoverService;

	public ReferenceListingHoverPlugin(PluginTool tool) {
		super(tool);
		referenceHoverService = new ReferenceListingHover(tool);
		registerServiceProvided(ListingHoverService.class, referenceHoverService);
	}

	@Override
	public void init() {
		// The ReferenceHover is dependent on the CodeFormatService.
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			referenceHoverService.programClosed(ev.getProgram());
		}
	}

	@Override
	public void dispose() {
		referenceHoverService.dispose();
	}
}
