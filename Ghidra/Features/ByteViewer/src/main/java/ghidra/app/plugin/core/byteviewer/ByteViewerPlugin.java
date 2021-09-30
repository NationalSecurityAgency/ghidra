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
package ghidra.app.plugin.core.byteviewer;

import java.util.Iterator;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;

/**
 * Visible Plugin to show ByteBlock data in various formats.
 */
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.BYTE_VIEWER,
	shortDescription = "Displays bytes in memory",
	description = "Provides a component for showing the bytes in memory.  " +
		"Additional plugins provide capabilites for this plugin" +
		" to show the bytes in various formats (e.g., hex, octal, decimal)." +
		"  The hex format plugin is loaded by default when this plugin is loaded.",
	servicesRequired = {
		ProgramManager.class, GoToService.class, NavigationHistoryService.class,
		ClipboardService.class,
	},
	eventsConsumed = {
		ProgramLocationPluginEvent.class, ProgramActivatedPluginEvent.class,
		ProgramSelectionPluginEvent.class, ProgramHighlightPluginEvent.class,
		ProgramClosedPluginEvent.class, ByteBlockChangePluginEvent.class,
	},
	eventsProduced = {
		ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class,
		ByteBlockChangePluginEvent.class,
	})
public class ByteViewerPlugin extends AbstractByteViewerPlugin<ProgramByteViewerComponentProvider> {

	public ByteViewerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected ProgramByteViewerComponentProvider createProvider(boolean isConnected) {
		return new ProgramByteViewerComponentProvider(tool, this, isConnected);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			programClosed(program);
			return;
		}

		if (event instanceof ProgramActivatedPluginEvent) {
			currentProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			currentLocation = ((ProgramLocationPluginEvent) event).getLocation();
		}

		connectedProvider.doHandleEvent(event);
	}

	void programClosed(Program closedProgram) {
		Iterator<ProgramByteViewerComponentProvider> iterator = disconnectedProviders.iterator();
		while (iterator.hasNext()) {
			ProgramByteViewerComponentProvider provider = iterator.next();
			if (provider.getProgram() == closedProgram) {
				iterator.remove();
				removeProvider(provider);
			}
		}
	}

	@Override
	public void updateLocation(ProgramByteViewerComponentProvider provider,
			ProgramLocationPluginEvent event, boolean export) {

		if (eventsDisabled()) {
			return;
		}

		if (provider == connectedProvider) {
			fireProgramLocationPluginEvent(provider, event);
		}
		else if (export) {
			exportLocation(provider.getProgram(), event.getLocation());
		}
	}

	@Override
	public void fireProgramLocationPluginEvent(ProgramByteViewerComponentProvider provider,
			ProgramLocationPluginEvent event) {

		if (SystemUtilities.isEqual(event.getLocation(), currentLocation)) {
			return;
		}

		currentLocation = event.getLocation();
		if (provider == connectedProvider) {
			firePluginEvent(event);
		}
	}

	@Override
	public void updateSelection(ByteViewerComponentProvider provider,
			ProgramSelectionPluginEvent event, Program program) {
		if (provider == connectedProvider) {
			firePluginEvent(event);
		}
	}

	@Override
	public void highlightChanged(ByteViewerComponentProvider provider,
			ProgramSelection highlight) {
		if (provider == connectedProvider) {
			tool.firePluginEvent(new ProgramHighlightPluginEvent(getName(), highlight,
				connectedProvider.getProgram()));
		}
	}
}
