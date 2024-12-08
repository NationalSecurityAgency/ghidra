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

import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.FirstTimeAnalyzedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
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
	description = 
		"This plugin watches for new programs being opened and determines the best " + 
		"starting location for the listing view.  It is also responsible for storing " +
		"and restoring the program's last listing location when reopened.",
	servicesRequired = { GoToService.class },
	eventsConsumed = { FirstTimeAnalyzedPluginEvent.class }
)
//@formatter:on
public class ProgramStartingLocationPlugin extends ProgramPlugin {

	public enum NonActiveProgramState {
		NEWLY_OPENED,
		RESTORED,
		FIRST_ANALYSIS_COMPLETED
	}

	private static final String LAST_LOCATION_PROPERTY = "LAST_PROGRAM_LOCATION";
	private ProgramStartingLocationOptions startOptions;
	private WeakHashMap<Program, ProgramLocation> currentLocationsMap = new WeakHashMap<>();
	private WeakHashMap<Program, ProgramLocation> startLocationsMap = new WeakHashMap<>();
	private WeakHashMap<Program, NonActiveProgramState> programStateMap = new WeakHashMap<>();

	public ProgramStartingLocationPlugin(PluginTool tool) {
		super(tool);
		startOptions = new ProgramStartingLocationOptions(tool);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof FirstTimeAnalyzedPluginEvent ev) {
			Program program = ev.getProgram();
			if (program != null) {
				// call firstAnalysisCompleted() in its own swing thread so we don't block
				// the event broadcast thread with a GUI modal popup
				Swing.runLater(() -> firstAnalysisCompleted(program));
			}
		}
	}

	private void firstAnalysisCompleted(Program program) {
		if (program.equals(currentProgram)) {
			processFirstAnalysisCompleted();
		}
		else {
			programStateMap.put(program, NonActiveProgramState.FIRST_ANALYSIS_COMPLETED);
		}
	}

	@Override
	protected void programOpened(Program program) {
		if (tool.isRestoringDataState()) {
			programStateMap.put(program, NonActiveProgramState.RESTORED);
		}
		else {
			programStateMap.put(program, NonActiveProgramState.NEWLY_OPENED);
		}
	}

	@Override
	protected void programClosed(Program program) {
		ProgramLocation lastLocation = currentLocationsMap.remove(program);
		if (lastLocation == null) {
			return;
		}
		// store a program's last location in the associated user program data.
		ProgramUserData programUserData = program.getProgramUserData();
		SaveState saveState = new SaveState("Last_Location");
		lastLocation.saveState(saveState);
		String xmlString = XmlUtilities.toString(saveState.saveToXml());
		programUserData.setStringProperty(LAST_LOCATION_PROPERTY, xmlString);

		programStateMap.remove(program);
		currentLocationsMap.remove(program);

	}

	@Override
	protected void postProgramActivated(Program program) {
		NonActiveProgramState state = programStateMap.remove(program);
		if (state == NonActiveProgramState.NEWLY_OPENED) {
			setStartingLocationForNewProgram();
		}
		else if (state == NonActiveProgramState.FIRST_ANALYSIS_COMPLETED) {
			processFirstAnalysisCompleted();
		}
	}

	private void processFirstAnalysisCompleted() {
		boolean shouldAskToRepostion = startOptions.shouldAskToRepostionAfterAnalysis();
		boolean autoRepositionIfNotMoved = startOptions.shouldAutoRepositionIfNotMoved();

		if (!shouldAskToRepostion && !autoRepositionIfNotMoved) {
			return;
		}

		// if analysis didn't find any starting symbol, nothing to do
		Symbol symbol = findStartingSymbol(currentProgram);
		if (symbol == null) {
			return;
		}

		// if already at the symbol's address, don't do anything
		if (currentLocation != null && currentLocation.getAddress().equals(symbol.getAddress())) {
			return;
		}

		if (autoRepositionIfNotMoved && isProgramAtStartingLocation()) {
			gotoLocation(symbol.getProgramLocation());
		}
		else if (shouldAskToRepostion && askToPositionProgram(symbol)) {
			gotoLocation(symbol.getProgramLocation());
		}
	}

	private boolean askToPositionProgram(Symbol symbol) {
		int result = OptionDialog.showYesNoDialog(null, "Reposition Program?",
			"Analysis found the symbol \"" + symbol.getName() +
				"\".  Would you like to go to that symbol?");
		return result == OptionDialog.YES_OPTION;
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (loc != null) {
			Program program = loc.getProgram();
			currentLocationsMap.put(program, loc);

			// the startLocationsMap only gets updated with the first location
			if (!startLocationsMap.containsKey(program)) {
				startLocationsMap.put(program, loc);
			}
		}
	}

	private void setStartingLocationForNewProgram() {
		if (currentProgram == null) {
			return;
		}

		ProgramLocation location = getStartingProgramLocation(currentProgram);
		if (location != null) {
			gotoLocation(location);
			startLocationsMap.put(currentProgram, location);
		}

	}

	private void gotoLocation(ProgramLocation location) {
		GoToService gotoService = tool.getService(GoToService.class);
		gotoService.goTo(location);
	}

	private boolean isProgramAtStartingLocation() {
		ProgramLocation startLocation = startLocationsMap.get(currentProgram);
		if (startLocation == null || currentLocation == null) {
			return true;
		}
		// just compare address, analysis may have tweaked the current location even
		// the user didn't move
		return startLocation.getAddress().equals(currentLocation.getAddress());
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
				Symbol symbol = findStartingSymbol(program);
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

	private Symbol findStartingSymbol(Program program) {
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
