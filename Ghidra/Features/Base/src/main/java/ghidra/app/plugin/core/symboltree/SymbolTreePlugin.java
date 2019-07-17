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
package ghidra.app.plugin.core.symboltree;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Symbol Tree",
	description = "This plugin shows the symbols from the program " +
			"in a tree hierarchy.  All symbols (except for the global namespace symbol)" +
			" have a parent symbol.  From the tree, symbols can be renamed, deleted, or " +
			"reorganized.",
	eventsConsumed = { ProgramActivatedPluginEvent.class, ProgramLocationPluginEvent.class, ProgramClosedPluginEvent.class }
)
//@formatter:on
public class SymbolTreePlugin extends Plugin {

	public static final String PLUGIN_NAME = "SymbolTreePlugin";

	private SymbolTreeProvider provider;
	private Program program;
	private GoToService goToService;
	private boolean processingGoTo;

	public SymbolTreePlugin(PluginTool tool) {
		super(tool);
		provider = new SymbolTreeProvider(tool, this);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program oldProgram = program;
			program = ev.getActiveProgram();
			if (oldProgram != null) {
				provider.programDeactivated(oldProgram);
			}
			if (program != null) {
				provider.programActivated(program);
			}
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			provider.programClosed(((ProgramClosedPluginEvent) event).getProgram());
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			if (processingGoTo) {
				return; // no bouncing!!
			}

			ProgramLocation loc = ((ProgramLocationPluginEvent) event).getLocation();
			provider.locationChanged(loc);
		}
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
		provider.dispose();
		program = null;
	}

	@Override
	public void readConfigState(SaveState saveState) {
		provider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		provider.writeConfigState(saveState);
	}

	public void goTo(Symbol symbol) {

		SymbolType type = symbol.getSymbolType();
		if (type.isNamespace() && type != SymbolType.FUNCTION) {
			tool.setStatusInfo("Can not navigate to " + (symbol.isExternal() ? "external " : "") +
				type.toString() + " symbol: " + symbol.getName());
			return;
		}

		boolean success = false;
		String reason = "";
		if (goToService != null) {
			processingGoTo = true;
			try {
				ProgramLocation loc = symbol.getProgramLocation();
				if (symbol.getAddress().isExternalAddress()) {
					goToService.goTo(symbol.getAddress(), program);
					return; // let GoTo service provide status messages
				}
				else if (loc != null) {
					reason = " (not in-memory)";
					success = goToService.goTo(loc);
				}
			}
			finally {
				processingGoTo = false;
			}
		}

		if (!success) {
			tool.setStatusInfo("Can not navigate to " + (symbol.isExternal() ? "external " : "") +
				type.toString() + " symbol: " + symbol.getName() + reason);
		}
	}

	public void goTo(ExternalLocation extLoc) {
		goToService.goToExternalLocation(extLoc, false);
	}

	public Program getProgram() {
		return program;
	}

	SymbolTreeProvider getProvider() {
		return provider;
	}
}
