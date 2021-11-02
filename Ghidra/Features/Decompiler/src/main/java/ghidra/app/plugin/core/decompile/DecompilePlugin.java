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
package ghidra.app.plugin.core.decompile;

import java.util.*;

import org.jdom.Element;

import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.SwingUpdateManager;

/**
 * Plugin for producing a high-level C interpretation of assembly functions.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Decompiler",
	description = "Plugin for producing high-level decompilation",
	servicesRequired = {
		GoToService.class, NavigationHistoryService.class, ClipboardService.class,
		DataTypeManagerService.class /*, ProgramManager.class */
	},
	eventsConsumed = {
		ProgramActivatedPluginEvent.class, ProgramOpenedPluginEvent.class,
		ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class,
		ProgramClosedPluginEvent.class
	}
)
//@formatter:on
public class DecompilePlugin extends Plugin {

	private PrimaryDecompilerProvider connectedProvider;
	private List<DecompilerProvider> disconnectedProviders;

	private Program currentProgram;
	private ProgramLocation currentLocation;
	private ProgramSelection currentSelection;

	/**
	 * Delay location changes to allow location events to settle down.
	 * This happens when a readDataState occurs when a tool is restored
	 * or when switching program tabs.
	 */
	SwingUpdateManager delayedLocationUpdateMgr = new SwingUpdateManager(200, 200, () -> {
		if (currentLocation != null) {
			connectedProvider.setLocation(currentLocation, null);
		}
	});

	public DecompilePlugin(PluginTool tool) {
		super(tool);

		disconnectedProviders = new ArrayList<>();
		connectedProvider = new PrimaryDecompilerProvider(this);
	}

	@Override
	protected void init() {
		ClipboardService clipboardService = tool.getService(ClipboardService.class);
		if (clipboardService != null) {
			connectedProvider.setClipboardService(clipboardService);
			for (DecompilerProvider provider : disconnectedProviders) {
				provider.setClipboardService(clipboardService);
			}
		}
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (connectedProvider != null) {
			connectedProvider.writeDataState(saveState);
		}
		saveState.putInt("Num Disconnected", disconnectedProviders.size());
		int i = 0;
		for (DecompilerProvider provider : disconnectedProviders) {
			SaveState providerSaveState = new SaveState();
			DomainFile df = provider.getProgram().getDomainFile();
			if (df.getParent() == null) {
				continue; // not contained within project
			}
			String programPathname = df.getPathname();
			providerSaveState.putString("Program Path", programPathname);
			provider.writeDataState(providerSaveState);
			String elementName = "Provider" + i;
			saveState.putXmlElement(elementName, providerSaveState.saveToXml());
			i++;
		}
	}

	@Override
	public void readDataState(SaveState saveState) {
		ProgramManager programManagerService = tool.getService(ProgramManager.class);

		if (connectedProvider != null) {
			connectedProvider.readDataState(saveState);
		}
		int numDisconnected = saveState.getInt("Num Disconnected", 0);
		for (int i = 0; i < numDisconnected; i++) {
			Element xmlElement = saveState.getXmlElement("Provider" + i);
			SaveState providerSaveState = new SaveState(xmlElement);
			String programPath = providerSaveState.getString("Program Path", "");
			DomainFile file = tool.getProject().getProjectData().getFile(programPath);
			if (file == null) {
				continue;
			}
			Program program = programManagerService.openProgram(file);
			if (program != null) {
				DecompilerProvider provider = createNewDisconnectedProvider();
				provider.doSetProgram(program);
				provider.readDataState(providerSaveState);
			}
		}
	}

	DecompilerProvider createNewDisconnectedProvider() {
		DecompilerProvider decompilerProvider = new DecompilerProvider(this, false);
		decompilerProvider.setClipboardService(tool.getService(ClipboardService.class));
		disconnectedProviders.add(decompilerProvider);
		tool.showComponentProvider(decompilerProvider, true);
		return decompilerProvider;
	}

	@Override
	public void dispose() {

		currentProgram = null;

		if (connectedProvider != null) {
			removeProvider(connectedProvider);
		}
		for (DecompilerProvider provider : disconnectedProviders) {
			removeProvider(provider);
		}
		disconnectedProviders.clear();

	}

	void exportLocation(Program program, ProgramLocation location) {
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			service.goTo(location, program);
		}
	}

	void updateSelection(DecompilerProvider provider, Program selProgram,
			ProgramSelection selection) {
		if (provider == connectedProvider) {
			firePluginEvent(new ProgramSelectionPluginEvent(name, selection, selProgram));
		}
	}

	void closeProvider(DecompilerProvider provider) {
		if (provider == connectedProvider) {
			tool.showComponentProvider(provider, false);
		}
		else {
			disconnectedProviders.remove(provider);
			removeProvider(provider);
		}
	}

	void locationChanged(DecompilerProvider provider, ProgramLocation location) {
		if (provider == connectedProvider) {
			firePluginEvent(new ProgramLocationPluginEvent(name, location, location.getProgram()));
		}
	}

	public void selectionChanged(DecompilerProvider provider, ProgramSelection selection) {
		if (provider == connectedProvider) {
			firePluginEvent(new ProgramSelectionPluginEvent(name, selection, currentProgram));
		}
	}

	private void removeProvider(DecompilerProvider provider) {
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

	/**
	 * Process the plugin event; delegates the processing to the
	 * byte block.
	 */
	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			programClosed(program);
			return;
		}
		if (connectedProvider == null) {
			return;
		}

		if (event instanceof ProgramActivatedPluginEvent) {
			currentProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
			connectedProvider.doSetProgram(currentProgram);
			if (currentProgram != null) {
				SpecExtension.registerOptions(currentProgram);
			}
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocation location = ((ProgramLocationPluginEvent) event).getLocation();
			Address address = location.getAddress();
			if (address.isExternalAddress()) {
				return;
			}
			if (currentProgram != null) {
				Listing listing = currentProgram.getListing();
				CodeUnit codeUnit = listing.getCodeUnitContaining(address);
				if (codeUnit instanceof Data) {
					return;
				}
			}
			currentLocation = location;
			// delay location change to allow immediate location changes to
			// settle down.  This happens when switching program tabs in
			// code browser which produces multiple location changes
			delayedLocationUpdateMgr.updateLater();
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			currentSelection = ((ProgramSelectionPluginEvent) event).getSelection();
			connectedProvider.setSelection(currentSelection);
		}

	}

	private void programClosed(Program closedProgram) {
		Iterator<DecompilerProvider> iterator = disconnectedProviders.iterator();
		while (iterator.hasNext()) {
			DecompilerProvider provider = iterator.next();
			if (provider.getProgram() == closedProgram) {
				iterator.remove();
				removeProvider(provider);
			}
		}
		if (connectedProvider != null) {
			connectedProvider.programClosed(closedProgram);
		}
	}

	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == DecompilerHoverService.class) {
			DecompilerHoverService hoverService = (DecompilerHoverService) service;
			connectedProvider.getDecompilerPanel().addHoverService(hoverService);
			for (DecompilerProvider provider : disconnectedProviders) {
				provider.getDecompilerPanel().addHoverService(hoverService);
			}
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == DecompilerHoverService.class) {
			DecompilerHoverService hoverService = (DecompilerHoverService) service;
			connectedProvider.getDecompilerPanel().removeHoverService(hoverService);
			for (DecompilerProvider provider : disconnectedProviders) {
				provider.getDecompilerPanel().removeHoverService(hoverService);
			}
		}
	}
}
