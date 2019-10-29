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

import java.util.*;

import org.jdom.Element;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;
import utility.function.Callback;

/**
 * Visible Plugin to show ByteBlock data in various formats.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.BYTE_VIEWER,
	shortDescription = "Displays bytes in memory",
	description = "Provides a component for showing the bytes in memory.  " +
			"Additional plugins provide capabilites for this plugin" +
			" to show the bytes in various formats (e.g., hex, octal, decimal)." +
			"  The hex format plugin is loaded by default when this " + "plugin is loaded.",
	servicesRequired = { ProgramManager.class, GoToService.class, NavigationHistoryService.class, ClipboardService.class },
	eventsConsumed = {
		ProgramLocationPluginEvent.class, ProgramActivatedPluginEvent.class,
		ProgramSelectionPluginEvent.class, ProgramHighlightPluginEvent.class, ProgramClosedPluginEvent.class,
		ByteBlockChangePluginEvent.class },
	eventsProduced = { ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class, ByteBlockChangePluginEvent.class }
)
//@formatter:on
public class ByteViewerPlugin extends Plugin {

	private Program currentProgram;
	private boolean areEventsDisabled;
	private ProgramLocation currentLocation;

	private ProgramByteViewerComponentProvider connectedProvider;

	private List<ProgramByteViewerComponentProvider> disconnectedProviders = new ArrayList<>();

	public ByteViewerPlugin(PluginTool tool) {
		super(tool);

		connectedProvider = new ProgramByteViewerComponentProvider(tool, this, true);
	}

	protected void showConnectedProvider() {
		tool.showComponentProvider(connectedProvider, true);
	}

	@Override
	protected void init() {
		ClipboardService clipboardService = tool.getService(ClipboardService.class);
		if (clipboardService != null) {
			connectedProvider.setClipboardService(clipboardService);
			for (ProgramByteViewerComponentProvider provider : disconnectedProviders) {
				provider.setClipboardService(clipboardService);
			}
		}
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should remove
	 * itself from anything that it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		removeProvider(connectedProvider);
		for (ProgramByteViewerComponentProvider provider : disconnectedProviders) {
			removeProvider(provider);
		}
		disconnectedProviders.clear();
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

	/**
	 * Tells a Plugin to write any data-independent (preferences)
	 * properties to the output stream.
	 */
	@Override
	public void writeConfigState(SaveState saveState) {
		connectedProvider.writeConfigState(saveState);
	}

	/**
	 * Tells the Plugin to read its data-independent (preferences)
	 * properties from the input stream.
	 */
	@Override
	public void readConfigState(SaveState saveState) {
		connectedProvider.readConfigState(saveState);
	}

	/**
	 * Read data state; called after readConfigState(). Events generated
	 * by plugins we depend on should have been already been thrown by the
	 * time this method is called.
	 */
	@Override
	public void readDataState(SaveState saveState) {

		doWithEventsDisabled(() -> {

			ProgramManager programManagerService = tool.getService(ProgramManager.class);

			connectedProvider.readDataState(saveState);

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
					ProgramByteViewerComponentProvider provider =
						new ProgramByteViewerComponentProvider(tool, this, false);
					provider.doSetProgram(program);
					provider.readConfigState(providerSaveState);
					provider.readDataState(providerSaveState);
					tool.showComponentProvider(provider, true);
					addProvider(provider);
				}
			}

		});
	}

	/**
	 * Tells the Plugin to write any data-dependent state to the
	 * output stream.
	 */
	@Override
	public void writeDataState(SaveState saveState) {
		connectedProvider.writeDataState(saveState);
		saveState.putInt("Num Disconnected", disconnectedProviders.size());
		int i = 0;
		for (ProgramByteViewerComponentProvider provider : disconnectedProviders) {
			SaveState providerSaveState = new SaveState();
			DomainFile df = provider.getProgram().getDomainFile();
			if (df.getParent() == null) {
				continue; // not contained within project
			}
			String programPathname = df.getPathname();
			providerSaveState.putString("Program Path", programPathname);
			provider.writeConfigState(providerSaveState);
			provider.writeDataState(providerSaveState);
			String elementName = "Provider" + i;
			saveState.putXmlElement(elementName, providerSaveState.saveToXml());
			i++;
		}
	}

	@Override
	public Object getUndoRedoState(DomainObject domainObject) {
		Map<Long, Object> stateMap = new HashMap<>();

		addUndoRedoState(stateMap, domainObject, connectedProvider);

		for (ProgramByteViewerComponentProvider provider : disconnectedProviders) {
			addUndoRedoState(stateMap, domainObject, provider);
		}

		if (stateMap.isEmpty()) {
			return null;
		}
		return stateMap;
	}

	private void addUndoRedoState(Map<Long, Object> stateMap, DomainObject domainObject,
			ProgramByteViewerComponentProvider provider) {
		if (provider == null) {
			return;
		}
		Object state = provider.getUndoRedoState(domainObject);
		if (state != null) {
			stateMap.put(provider.getInstanceID(), state);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void restoreUndoRedoState(DomainObject domainObject, Object state) {
		Map<Long, Object> stateMap = (Map<Long, Object>) state;
		restoreUndoRedoState(stateMap, domainObject, connectedProvider);
		for (ProgramByteViewerComponentProvider provider : disconnectedProviders) {
			restoreUndoRedoState(stateMap, domainObject, provider);
		}

	}

	private void restoreUndoRedoState(Map<Long, Object> stateMap, DomainObject domainObject,
			ProgramByteViewerComponentProvider provider) {
		if (provider == null) {
			return;
		}
		Object state = stateMap.get(provider.getInstanceID());
		if (state != null) {
			provider.restoreUndoRedoState(domainObject, state);
		}
	}

	@Override
	public Object getTransientState() {
		Object[] state = new Object[2];

		SaveState ss = new SaveState();
		connectedProvider.writeDataState(ss);

		state[0] = ss;
		state[1] = connectedProvider.getCurrentSelection();

		return state;
	}

	@Override
	public void restoreTransientState(Object objectState) {

		doWithEventsDisabled(() -> {
			Object[] state = (Object[]) objectState;
			connectedProvider.restoreLocation((SaveState) state[0]);
			connectedProvider.setSelection((ProgramSelection) state[1]);
		});
	}

	private void doWithEventsDisabled(Callback callback) {
		areEventsDisabled = true;
		try {
			callback.call();
		}
		finally {
			areEventsDisabled = false;
		}
	}

	private boolean eventsDisabled() {
		return areEventsDisabled;
	}

	void setStatusMessage(String msg) {
		tool.setStatusInfo(msg);
	}

	void addProvider(ProgramByteViewerComponentProvider provider) {
		disconnectedProviders.add(provider);
		provider.setClipboardService(tool.getService(ClipboardService.class));
	}

	Program getProgram() {
		return currentProgram;
	}

	// Silly Junits - only public until we move to the new multi-view system
	public ProgramByteViewerComponentProvider getProvider() {
		return connectedProvider;
	}

	public void updateSelection(ProgramByteViewerComponentProvider provider,
			ProgramSelectionPluginEvent event, Program program) {
		if (provider == connectedProvider) {
			firePluginEvent(event);
		}
	}

	public void highlightChanged(ProgramByteViewerComponentProvider provider,
			ProgramSelection highlight) {
		if (provider == connectedProvider) {
			tool.firePluginEvent(new ProgramHighlightPluginEvent(getName(), highlight,
				connectedProvider.getProgram()));
		}
	}

	public void closeProvider(ProgramByteViewerComponentProvider provider) {
		if (provider == connectedProvider) {
			tool.showComponentProvider(provider, false);
		}
		else {
			disconnectedProviders.remove(provider);
			removeProvider(provider);
		}
	}

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

	private void exportLocation(Program program, ProgramLocation location) {
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			service.goTo(location, program);
		}
	}

	private void removeProvider(ProgramByteViewerComponentProvider provider) {
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

}
