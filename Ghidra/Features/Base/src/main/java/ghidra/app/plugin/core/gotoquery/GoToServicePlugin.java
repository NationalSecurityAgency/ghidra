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
package ghidra.app.plugin.core.gotoquery;

import javax.swing.Icon;

import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.nav.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.navigation.GoToServiceImpl;
import ghidra.app.util.query.TableService;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Go To Service",
	description = "This plugin provides the service used by other plugins to " +
			"go to an address in the program, or to an address in another program." +
			" This plugin also handles wildcards to go a label that matches a query." +
			" When multiple hits for a query are found, the plugin shows the results " +
			"in a query results table.",
			servicesRequired = { TableService.class, ProgramManager.class, NavigationHistoryService.class },
			servicesProvided = { GoToService.class },
			eventsProduced = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public final class GoToServicePlugin extends ProgramPlugin {
	private GoToServiceImpl gotoService;
	private boolean disposed;

	/**
	 * Creates a new instance of the <CODE>GoToServicePlugin</CODE>
	 * @param plugintool the tool
	 */
	public GoToServicePlugin(PluginTool plugintool) {
		super(plugintool, true, true);

		gotoService = new GoToServiceImpl(this, new DefaultNavigatable());

		registerServiceProvided(GoToService.class, gotoService);

	}

	@Override
	protected void init() {
		NavigatableRegistry.registerNavigatable(tool, gotoService.getDefaultNavigatable());
	}

	@Override
	protected void dispose() {
		disposed = true;
		NavigatableRegistry.unregisterNavigatable(tool, gotoService.getDefaultNavigatable());
	}

	int getMaxHits() {
		Options opt = tool.getOptions(PluginConstants.SEARCH_OPTION_NAME);
		int maxSearchHits =
			opt.getInt(GhidraOptions.OPTION_SEARCH_LIMIT, PluginConstants.DEFAULT_SEARCH_LIMIT);

		return maxSearchHits;
	}

	GoToService getGotoService() {
		return gotoService;
	}

	private void updateCurrentProgram(Program p) {
		ProgramManager service = tool.getService(ProgramManager.class);
		if (service != null) {
			service.setCurrentProgram(p);
		}
	}

	class DefaultNavigatable implements Navigatable {
		private Navigatable focusedNavigatable;

		@Override
		public ProgramLocation getLocation() {
			return currentLocation;
		}

		@Override
		public boolean goTo(Program program, ProgramLocation location) {
			updateCurrentProgram(program);
			if (currentProgram != program) {
				return false;
			}
			firePluginEvent(new ProgramLocationPluginEvent(getName(), location, currentProgram));
			currentLocation = location;
			return true;
		}

		@Override
		public LocationMemento getMemento() {
			return new DefaultNavigatableLocationMemento(currentProgram, currentLocation, tool);
		}

		@Override
		public void setMemento(LocationMemento memento) {
			DefaultNavigatableLocationMemento defaultMemento =
				(DefaultNavigatableLocationMemento) memento;
			defaultMemento.setMementos();
			focusedNavigatable = defaultMemento.getFocusedNavigatable();
		}

		@Override
		public Program getProgram() {
			return currentProgram;
		}

		@Override
		public Icon getNavigatableIcon() {
			return null;
		}

		@Override
		public boolean isConnected() {
			// the default is considered to always be connected
			return true;
		}

		@Override
		public boolean supportsMarkers() {
			return isConnected();
		}

		@Override
		public long getInstanceID() {
			return Navigatable.DEFAULT_NAVIGATABLE_ID;
		}

		@Override
		public boolean isVisible() {
			return true;
		}

		@Override
		public boolean isDisposed() {
			return disposed;
		}

		@Override
		public void requestFocus() {
			if (focusedNavigatable != null && focusedNavigatable.isVisible()) {
				focusedNavigatable.requestFocus();
				focusedNavigatable = null;
			}
		}

		@Override
		public void addNavigatableListener(NavigatableRemovalListener listener) {
			// do nothing, default Navigatable never goes away
		}

		@Override
		public void removeNavigatableListener(NavigatableRemovalListener listener) {
			// do nothing, default Navigatable never goes away
		}

		@Override
		public void setHighlight(ProgramSelection highlight) {
			tool.firePluginEvent(new ProgramHighlightPluginEvent(getName(), highlight,
				currentProgram));
		}

		@Override
		public boolean supportsHighlight() {
			return true;
		}

		@Override
		public void setSelection(ProgramSelection selection) {
			tool.firePluginEvent(new ProgramSelectionPluginEvent(getName(), selection,
				currentProgram));
		}

		@Override
		public ProgramSelection getSelection() {
			return currentSelection;
		}

		@Override
		public ProgramSelection getHighlight() {
			return currentHighlight;
		}

		@Override
		public String getTextSelection() {
			return null;
		}

		@Override
		public void removeHighlightProvider(HighlightProvider highlightProvider, Program program) {
			CodeViewerService service = tool.getService(CodeViewerService.class);
			if (service != null) {
				service.removeHighlightProvider(highlightProvider, program);
			}
		}

		@Override
		public void setHighlightProvider(HighlightProvider highlightProvider, Program program) {
			CodeViewerService service = tool.getService(CodeViewerService.class);
			if (service != null) {
				service.setHighlightProvider(highlightProvider, program);
			}
		}
	}

}
