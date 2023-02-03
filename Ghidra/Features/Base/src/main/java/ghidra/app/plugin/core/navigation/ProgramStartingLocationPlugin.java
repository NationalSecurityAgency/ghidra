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

import java.io.IOException;
import java.util.*;

import org.jdom.Element;
import org.jdom.JDOMException;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.xml.XmlUtilities;

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

	private static final String LAST_LOCATION_PROPERTY = "LAST_PROGRAM_LOCATION";
	private Program lastOpenedProgram;
	private ProgramStartingLocationOptions startOptions;
	private Map<Program, ProgramLocation> lastLocationMap = new HashMap<>();

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
		if (startOptions.getStartLocationType() == StartLocationType.LOWEST_ADDRESS) {
			// this is what happens by default, so no need to do anything
			return;
		}
		lastOpenedProgram = program;
	}

	protected void programClosed(Program program) {
		ProgramLocation lastLocation = lastLocationMap.remove(program);
		if (lastLocation == null) {
			return;
		}
		// store a program's last location in the associated user program data.
		ProgramUserData programUserData = program.getProgramUserData();
		SaveState saveState = new SaveState("Last_Location");
		lastLocation.saveState(saveState);
		String xmlString = XmlUtilities.toString(saveState.saveToXml());
		programUserData.setStringProperty(LAST_LOCATION_PROPERTY, xmlString);

	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);
		if (program == lastOpenedProgram) {
			Swing.runLater(this::setStartingLocationForNewProgram);
		}
		lastOpenedProgram = null;
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (loc != null) {
			Program program = loc.getProgram();
			lastLocationMap.put(program, loc);
		}
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
		switch (startOptions.getStartLocationType()) {
			case LAST_LOCATION:
				ProgramLocation lastLocation = getLastSavedLocation(program);
				if (lastLocation != null) {
					return lastLocation;
				}
				// fall through and try symbol name
			case SYMBOL_NAME:
				Symbol symbol = fingStartingSymbol(program);
				if (symbol != null) {
					return symbol.getProgramLocation();
				}
				// fall through and try to find the lowest code block
			case LOWEST_CODE_BLOCK:
				return findLowestCodeBlockLocation(program);
			case LOWEST_ADDRESS:
			default:
				return null;	// the program opens to lowest address anyway, so nothing to do
		}
	}

	private ProgramLocation getLastSavedLocation(Program program) {
		ProgramUserData programUserData = program.getProgramUserData();
		String value = programUserData.getStringProperty(LAST_LOCATION_PROPERTY, null);
		if (value == null) {
			return null;
		}
		try {
			Element element = XmlUtilities.fromString(value);
			SaveState saveState = new SaveState(element);
			return ProgramLocation.getLocation(program, saveState);
		}
		catch (JDOMException | IOException e) {
			return null;
		}
	}

	private Symbol fingStartingSymbol(Program program) {
		List<String> symbolNames = startOptions.getStartingSymbolNames();
		boolean useUnderscores = startOptions.useUnderscorePrefixes();
		for (String symbolName : symbolNames) {
			Symbol symbol = findSymbol(program, symbolName, useUnderscores);
			if (symbol != null) {
				return symbol;
			}
		}
		return null;
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
