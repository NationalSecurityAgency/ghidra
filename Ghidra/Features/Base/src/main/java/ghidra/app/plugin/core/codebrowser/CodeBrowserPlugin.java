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
package ghidra.app.plugin.core.codebrowser;

import java.util.Iterator;

import org.jdom.Element;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Code Viewer",
	description = "This plugin provides the main program listing display window. " +
		"It also includes the header component which allows the various " +
		"program fields to be arranged as desired.  In addition, this plugin " +
		"provides the \"CodeViewerService\" which allows other plugins to extend " +
		"the basic functionality to include such features as flow arrows, " +
		"margin markers and difference " +
		"tracking.  The listing component created by this plugin generates " +
		"ProgramLocation events and ProgramSelection events as the user moves " +
		"the cursor and makes selections respectively.",
	servicesRequired = { ProgramManager.class, GoToService.class,
		ClipboardService.class /*, TableService.class */ },
	servicesProvided = { CodeViewerService.class, CodeFormatService.class,
		FieldMouseHandlerService.class },
	eventsConsumed = { ProgramSelectionPluginEvent.class, ProgramActivatedPluginEvent.class,
		ProgramClosedPluginEvent.class, ProgramLocationPluginEvent.class,
		ViewChangedPluginEvent.class, ProgramHighlightPluginEvent.class },
	eventsProduced = { ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class })
public class CodeBrowserPlugin extends AbstractCodeBrowserPlugin<CodeViewerProvider> {

	public CodeBrowserPlugin(PluginTool tool) {
		super(tool);

		registerServiceProvided(FieldMouseHandlerService.class,
			connectedProvider.getFieldNavigator());
	}

	@Override
	protected CodeViewerProvider createProvider(FormatManager formatManager, boolean isConnected) {
		return new CodeViewerProvider(this, formatManager, isConnected);
	}

	@Override
	public void highlightChanged(CodeViewerProvider provider, ProgramSelection highlight) {
		MarkerSet highlightMarkers = getHighlightMarkers(currentProgram);
		if (highlightMarkers != null) {
			highlightMarkers.clearAll();
		}
		if (highlight != null && currentProgram != null) {
			if (highlightMarkers != null) {
				highlightMarkers.add(highlight);
			}
		}
		if (provider == connectedProvider) {
			tool.firePluginEvent(new ProgramHighlightPluginEvent(getName(), highlight,
				connectedProvider.getProgram()));
		}
	}

	/**
	 * Interface method called to process a plugin event.
	 */
	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			programClosed(program);
			return;
		}
		if (event instanceof ProgramActivatedPluginEvent) {
			if (currentProgram != null) {
				currentProgram.removeListener(this);
			}
			ProgramActivatedPluginEvent evt = (ProgramActivatedPluginEvent) event;
			clearMarkers(currentProgram); // do this just before changing the program

			currentProgram = evt.getActiveProgram();
			if (currentProgram != null) {
				currentProgram.addListener(this);
				currentView = currentProgram.getMemory();
			}
			else {
				currentView = new AddressSet();
			}
			connectedProvider.doSetProgram(currentProgram);

			updateHighlightProvider();
			updateBackgroundColorModel();
			setHighlight(new FieldSelection());
			AddressFactory currentAddressFactory =
				(currentProgram != null) ? currentProgram.getAddressFactory() : null;
			setSelection(new ProgramSelection(currentAddressFactory));
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent evt = (ProgramLocationPluginEvent) event;
			ProgramLocation location = evt.getLocation();
			if (!connectedProvider.setLocation(location)) {
				if (viewManager != null) {
					connectedProvider.setView(viewManager.addToView(location));
					ListingPanel lp = connectedProvider.getListingPanel();
					lp.goTo(location, true);
				}
			}
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelectionPluginEvent evt = (ProgramSelectionPluginEvent) event;
			setSelection(evt.getSelection());
		}
		else if (event instanceof ProgramHighlightPluginEvent) {
			ProgramHighlightPluginEvent evt = (ProgramHighlightPluginEvent) event;
			if (evt.getProgram() == currentProgram) {
				setHighlight(evt.getHighlight());
			}
		}
		else if (event instanceof ViewChangedPluginEvent) {
			AddressSet view = ((ViewChangedPluginEvent) event).getView();
			viewChanged(view);
		}
	}

	protected void programClosed(Program closedProgram) {
		Iterator<CodeViewerProvider> iterator = disconnectedProviders.iterator();
		while (iterator.hasNext()) {
			CodeViewerProvider provider = iterator.next();
			if (provider.getProgram() == closedProgram) {
				iterator.remove();
				removeProvider(provider);
			}
		}
	}

	@Override
	public Object getTransientState() {
		Object[] state = new Object[5];
		FieldPanel fieldPanel = connectedProvider.getListingPanel().getFieldPanel();
		state[0] = fieldPanel.getViewerPosition();
		state[1] = connectedProvider.getLocation();
		state[2] = connectedProvider.getHighlight();
		state[3] = connectedProvider.getSelection();
		state[4] = currentView;
		return state;
	}

	@Override
	public void restoreTransientState(final Object objectState) {
		Object[] state = (Object[]) objectState;
		ViewerPosition vp = (ViewerPosition) state[0];
		ProgramLocation location = (ProgramLocation) state[1];
		ProgramSelection highlight = (ProgramSelection) state[2];
		ProgramSelection selection = (ProgramSelection) state[3];

		viewChanged((AddressSetView) state[4]);

		if (location != null) {
			connectedProvider.setLocation(location);
		}
		setHighlight(highlight);
		if (selection != null) {
			connectedProvider.setSelection(selection);
		}
		if (vp != null) {
			FieldPanel fieldPanel = connectedProvider.getListingPanel().getFieldPanel();
			fieldPanel.setViewerPosition(vp.getIndex(), vp.getXOffset(), vp.getYOffset());
		}
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (connectedProvider != null) {
			connectedProvider.writeDataState(saveState);
		}
		saveState.putInt("Num Disconnected", disconnectedProviders.size());
		int i = 0;
		for (CodeViewerProvider provider : disconnectedProviders) {
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
		FieldSelection highlight =
			connectedProvider.getListingPanel().getFieldPanel().getHighlight();
		highlight.save(saveState);
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
				CodeViewerProvider provider = createNewDisconnectedProvider();
				provider.doSetProgram(program);
				provider.readDataState(providerSaveState);
			}
		}

		FieldSelection highlight = new FieldSelection();
		highlight.load(saveState);
		if (!highlight.isEmpty()) {
			setHighlight(highlight);
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		formatMgr.saveState(saveState);
		connectedProvider.saveState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		formatMgr.readState(saveState);
		connectedProvider.readState(saveState);
	}

	@Override
	public void locationChanged(CodeViewerProvider provider, ProgramLocation location) {
		if (provider == connectedProvider) {
			MarkerSet cursorMarkers = getCursorMarkers(currentProgram);
			if (cursorMarkers != null) {
				cursorMarkers.clearAll();
				cursorMarkers.add(location.getAddress());
			}
			tool.firePluginEvent(new ProgramLocationPluginEvent(getName(), location,
				connectedProvider.getProgram()));
		}
	}

	@Override
	public ViewManagerService getViewManager(CodeViewerProvider codeViewerProvider) {
		if (codeViewerProvider == connectedProvider) {
			return viewManager;
		}
		return null;
	}
}
