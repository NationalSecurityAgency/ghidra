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
package ghidra.app.plugin.core.navigation;

import java.util.Collections;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Determines the starting location when a program is opened.",
	description = "This plugin watches for new programs being opened and determines the best starting location for the listing view.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class ProgramStartingLocationPlugin extends ProgramPlugin {

	private Program lastOpenedProgram;
	private ProgramStartingLocationOptions startOptions;

	public ProgramStartingLocationPlugin(PluginTool tool) {
		super(tool);
		startOptions = new ProgramStartingLocationOptions(tool);
	}

	@Override
	protected void programOpened(Program program) {
		// if the open program event is a result of restoring the tool's data state, don't 
		// interfere with the tool's restoration of the last location for that program
		if (tool.isRestoringDataState()) {
			return;
		}
		if (startOptions.shouldStartAtLowestAddress()) {
			// this is what happens by default, so no need to do anything
			return;
		}
		lastOpenedProgram = program;
	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);
		if (program == lastOpenedProgram) {
			Swing.runLater(this::setStartingLocationForNewProgram);
		}
		lastOpenedProgram = null;
	}

	private void setStartingLocationForNewProgram() {
		if (currentProgram == null) {
			return;
		}

		GoToService gotoService = tool.getService(GoToService.class);

		ProgramLocation location = getStartingProgramLocation(currentProgram);
		if (location != null) {
			gotoService.goTo(location);
		}

	}

	private ProgramLocation getStartingProgramLocation(Program program) {
		if (startOptions.shouldStartOnSymbol()) {
			List<String> symbolNames = startOptions.getStartingSymbolNames();
			boolean useUnderscores = startOptions.useUnderscorePrefixes();
			for (String symbolName : symbolNames) {
				Symbol symbol = findSymbol(program, symbolName, useUnderscores);
				if (symbol != null) {
					return symbol.getProgramLocation();
				}
			}
		}
		// if the option is start on first code block, or we couldn't find a symbol, try and
		// find the first executable code block
		return findLowestCodeBlockLocation(program);
	}

	private ProgramLocation findLowestCodeBlockLocation(Program program) {
		AddressSetView executeSet = program.getMemory().getExecuteSet();
		if (executeSet.isEmpty()) {
			return null;
		}
		return new ProgramLocation(program, executeSet.getMinAddress());
	}

	private Symbol findSymbol(Program program, String symbolName, boolean useUnderscores) {
		Symbol symbol = findSymbol(program, symbolName);
		if (symbol != null) {
			return symbol;
		}
		if (!useUnderscores) {
			return null;
		}
		symbol = findSymbol(program, "_" + symbolName);
		if (symbol != null) {
			return symbol;
		}
		return findSymbol(program, "__" + symbolName);
	}

	private Symbol findSymbol(Program program, String symbolName) {
		SymbolTable symbolTable = program.getSymbolTable();
		List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, null);
		if (symbols.isEmpty()) {
			return null;
		}
		if (symbols.size() > 1) {
			Collections.sort(symbols, (s1, s2) -> s1.getAddress().compareTo(s2.getAddress()));
		}
		return symbols.get(0);
	}

	@Override
	protected void dispose() {
		super.dispose();
		startOptions.dispose();
	}
}
