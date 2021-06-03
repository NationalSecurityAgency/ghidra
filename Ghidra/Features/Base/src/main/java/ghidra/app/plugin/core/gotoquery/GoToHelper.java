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

import java.util.Stack;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.OptionDialog;
import ghidra.app.cmd.refs.SetExternalNameCmd;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.services.NavigationHistoryService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.query.TableService;
import ghidra.framework.cmd.Command;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.table.AddressArrayTableModel;

public class GoToHelper {

	private PluginTool tool;

	private NavigationOptions navOptions; // needed to determine external address navigation behavior

	public GoToHelper(PluginTool tool) {
		this.tool = tool;
		navOptions = new NavigationOptions(tool);
	}

	public void dispose() {
		navOptions.dispose();
	}

	public NavigationOptions getOptions() {
		return navOptions;
	}

	public static ProgramLocation getProgramLocationForAddress(Address goToAddress,
			Program program) {
		if (program == null) {
			return null;
		}

		SymbolTable symTable = program.getSymbolTable();
		Symbol symbol = symTable.getPrimarySymbol(goToAddress);
		if (symbol != null) {
			return symbol.getProgramLocation();
		}

		if (goToAddress.isMemoryAddress()) {
			return new AddressFieldLocation(program, goToAddress);
		}
		return null;
	}

	public boolean goTo(final Navigatable navigatable, ProgramLocation loc, Program program) {
		if (loc == null || loc.getAddress() == null) {
			return false;
		}
		if (program == null) {
			program = findGoToProgram(navigatable.getProgram(), loc.getAddress());
		}
		if (program == null) {
			return false;
		}

		Address addr = loc.getAddress();
		if (addr.isExternalAddress()) {
			Symbol externalSym = program.getSymbolTable().getPrimarySymbol(addr);
			if (externalSym == null) {
				return false;
			}
			ExternalLocation externalLoc =
				program.getExternalManager().getExternalLocation(externalSym);

			// TODO - this seems like a mistake to always pass 'false' here; please doc why we
			//        wish to ignore the user options for when to navigate to external programs
			return goToExternalLinkage(navigatable, externalLoc, false);
		}

		Memory memory = program.getMemory();
		if (!memory.contains(addr)) {
			tool.setStatusInfo("Address not found in program memory: " + addr);
			return false;
		}

		saveLocation(navigatable);

		if (!navigatable.goTo(program, loc)) {
			return false;
		}

// If we want the goto to request focus then we will need to add a new parameter - you don't always
//       	want to request focus.
//       	// sometimes this gets call directly after creating a new provider window.  Need to
//       	// request focus in an invokeLater to give WindowManager a chance to create the component
//       	// hierarchy tree.
//       	SwingUtilities.invokeLater(new Runnable() {
//			public void run() {
//		       	navigatable.requestFocus();
//			}
//		});

		saveLocation(navigatable);

		return true;
	}

	private void saveLocation(Navigatable navigatable) {
		if (navigatable.getProgram() == null) {
			return;
		}
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (historyService != null) {
			historyService.addNewLocation(navigatable);
		}
	}

	public ProgramLocation getLocation(Program program, Address currentAddress,
			Address gotoAddress) {
		ProgramLocation loc = getProgramLocationForAddress(gotoAddress, program);
		if (loc != null) {
			return loc;
		}
		if (gotoAddress.isStackAddress() || gotoAddress.isRegisterAddress()) {
			// Convert stack/register address into variable address
			Function func = program.getFunctionManager().getFunctionContaining(currentAddress);
			if (func != null) {
				for (Variable v : func.getAllVariables()) {
					VariableStorage storage = v.getVariableStorage();
					if (storage.contains(gotoAddress)) {
						return new VariableNameFieldLocation(program, v, 0);
					}
				}
			}
		}

		SymbolTable symTable = program.getSymbolTable();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.getReference(currentAddress, gotoAddress, 0);
		Symbol symbol = symTable.getSymbol(ref);

		if (symbol != null) {
			return symbol.getProgramLocation();
		}
		return null;
	}

	/**
	 * GoTo external address linkage location (pointer or thunk) within the current program
	 * which is associated with the specified external location.
	 * <p>
	 * For those use cases which should not popup a window the popupAllowed
	 * option should be <b>false</b>.
	 * <p>
	 * This method will generally cause navigation to a linkage location associated with
	 * the specified external location.  A linkage location is either a pointer to the
	 * external location (identified by reference) or a thunk to the external
	 * location, provided the thunk does not reference a linkage pointer.  If more than one
	 * linkage location exists and popupAllowed is <b>true</b>, a table will be displayed allowing
	 * the user to navigate to any of the linkage locations.  If navigation is initiated from the
	 * only known linkage location, and popupAllowed is <b>true</b>, navigation to the external
	 * program will be attempted regardless of the current
	 * {@link NavigationOptions#isGotoExternalProgramEnabled} setting.
	 * @param nav Navigatable
	 * @param externalLoc external location
	 * @param popupAllowed if true a table may be displayed when multiple linkage locations
	 * exist, otherwise navigation to the first linkage location will be performed
	 * @return true if navigation was successful or a list of possible linkage locations
	 * was displayed.
	 */
	private boolean goToExternalLinkage(Navigatable nav, ExternalLocation externalLoc,
			boolean popupAllowed) {
		if (externalLoc == null) {
			return false;
		}

		Symbol externalSym = externalLoc.getSymbol();
		Program program = externalSym.getProgram();

		Address[] externalLinkageAddresses =
			NavigationUtils.getExternalLinkageAddresses(program, externalSym.getAddress());
		if (externalLinkageAddresses.length == 0) {
			tool.setStatusInfo("Failed to identify external linkage address for " +
				externalSym.getName(true) + ". Unable to perform navigation.", true);
			return false;
		}
		if (externalLinkageAddresses.length > 1) {
			if (popupAllowed) {
				// popup list of all possible linkage locations
				AddressArrayTableModel model = new AddressArrayTableModel("Goto: ", tool, program,
					externalLinkageAddresses, null);
				TableService service = tool.getService(TableService.class);
				service.showTable("Goto " + externalSym.getName(true) + " linkage location", "Goto",
					model, "Go To", nav);
				return true;
			}
			tool.setStatusInfo(
				"Multiple external linkage addresses found for " + externalSym.getName(true), true);
		}
		else if (popupAllowed) {
			ProgramLocation location = nav.getLocation();
			if (location != null && externalLinkageAddresses[0].equals(location.getAddress())) {
				// If current location is the linkage location and popupAllowed, ignore
				// navigation option and attempt to navigate to external program
				return goToExternalLocation(nav, externalLoc, false);
			}
		}

		ProgramLocation location =
			getProgramLocationForAddress(externalLinkageAddresses[0], program);
		return goTo(nav, location, program);
	}

	/**
	 * Navigate to either the external program location or address linkage location.
	 * This method will only navigate to the
	 * external program associated with the specified location if either checkNavigationOption
	 * is false, or the navigation option is set to Show External Program, or
	 * the current location is the same as the single linkage location.  See
	 * {@link #goToExternalLinkage(Navigatable, ExternalLocation, boolean)} method for
	 * external linkage navigation behavior.
	 * <p>
	 * If navigation to an external program will be performed, the associated program will
	 * be identified and the location within that program found.  Once this occurs, the
	 * external program will be opened within the current tool and navigation completed.  If an
	 * external program association has not yet been established, the user will be prompted to make
	 * an association if they choose before completing the navigation.
	 * @param nav Navigatable
	 * @param externalLocation external location
	 * @param checkNavigationOption if true the {@link NavigationOptions#isGotoExternalProgramEnabled}
	 * option will be used to determine if navigation to the external program will be
	 * attempted, or if navigation to the external linkage location within the current
	 * program will be attempted.  If false, only navigation to the external linkage will be
	 * attempted.
	 * @return true if navigation to the external program was successful or navigation to a
	 * linkage location was performed.
	 */
	public boolean goToExternalLocation(Navigatable nav, ExternalLocation externalLocation,
			boolean checkNavigationOption) {

		if (checkNavigationOption && !navOptions.isGotoExternalProgramEnabled()) {
			return goToExternalLinkage(nav, externalLocation, true);
		}

		Program externalProgram = openExternalProgram(externalLocation);
		if (externalProgram == null) {
			return false;
		}

		// try the address first if it exists
		Address addr = externalLocation.getAddress();
		if (addr != null && externalProgram.getMemory().contains(addr)) {
			goTo(nav, new AddressFieldLocation(externalProgram, addr), externalProgram);
			return true;
		}

		// then try the symbol
		Symbol symbol = getExternalSymbol(externalProgram, externalLocation);
		if (symbol != null) {
			goTo(nav, symbol.getProgramLocation(), externalProgram);
			return true;
		}

		performDefaultExternalProgramNavigation(nav, externalLocation, externalProgram, addr);
		return false; // return false because we did not go to the requested address
	}

	private Program openExternalProgram(ExternalLocation externalLocation) {

		if (externalLocation == null) {
			return null;
		}

		Symbol externalSym = externalLocation.getSymbol();
		Program program = externalSym.getProgram();
		String pathName = getExternalLibraryPath(externalLocation, program);
		if (pathName == null) {
			return null;
		}

		ProjectData pd = tool.getProject().getProjectData();
		DomainFile domainFile = pd.getFile(pathName);
		ProgramManager service = tool.getService(ProgramManager.class);
		if (domainFile == null || service == null) {
			tool.setStatusInfo("Unable to navigate to external location. " +
				"Destination program [" + externalLocation + "] does not exist.");
			return null;
		}

		return service.openProgram(domainFile, -1, ProgramManager.OPEN_VISIBLE);
	}

	private void performDefaultExternalProgramNavigation(Navigatable nav,
			ExternalLocation externalLocation, Program externalProgram, Address addr) {

		// failed to navigate to address or symbol; alert the user
		if (addr != null) {
			if (externalLocation.getSymbol().getSource() != SourceType.DEFAULT) {
				tool.setStatusInfo("Symbol [" + getExternalName(externalLocation) +
					"] does not exist, and address [" + addr + "] is not in memory.", true);
			}
			else {
				tool.setStatusInfo("Address [" + addr + "] is not in memory.", true);
			}
		}
		else {
			tool.setStatusInfo("Symbol [" + getExternalName(externalLocation) + "] does not exist.",
				true);
		}

		// navigate to top of external program
		AddressFieldLocation location =
			new AddressFieldLocation(externalProgram, externalProgram.getMinAddress());
		goTo(nav, location, externalProgram);
	}

	private String getExternalLibraryPath(ExternalLocation externalLocation, Program program) {

		ExternalManager externalManager = program.getExternalManager();
		String extProgName = externalLocation.getLibraryName();
		if (Library.UNKNOWN.equals(extProgName)) {
			tool.setStatusInfo(" External location refers to " + Library.UNKNOWN +
				" library. Unable to " + "perform navigation.", true);
			return null;
		}

		String pathName = externalManager.getExternalLibraryPath(extProgName);
		if (StringUtils.isBlank(pathName)) {
			createExternalAssociation(program, extProgName);
			pathName = externalManager.getExternalLibraryPath(extProgName);
		}

		if (StringUtils.isBlank(pathName)) {
			tool.setStatusInfo(" External location is not resolved. Unable to perform navigation.",
				true);
			return null;
		}

		return pathName;
	}

	private Stack<String> getExternalNamespaceStack(ExternalLocation externalLoc) {
		Symbol s = externalLoc.getSymbol();
		if (s.getSource() == SourceType.DEFAULT) {
			return null; // default name is not valid for external program
		}
		Stack<String> nameStack = new Stack<>();
		for (Namespace namespace =
			s.getParentNamespace(); !(namespace instanceof Library); namespace =
				namespace.getParentNamespace()) {
			nameStack.push(namespace.getName());
		}
		return nameStack;
	}

	private String getExternalName(ExternalLocation externalLoc) {

		String label = externalLoc.getOriginalImportedName();
		if (label != null) {
			return label;
		}

		Stack<String> nameStack = getExternalNamespaceStack(externalLoc);
		if (nameStack == null) {
			return null; // name is not valid for external program
		}
		StringBuilder buf = new StringBuilder();
		while (!nameStack.isEmpty()) {
			buf.append(nameStack.pop());
			buf.append(Namespace.DELIMITER);
		}
		buf.append(externalLoc.getLabel());
		return buf.toString();
	}

	private Symbol getExternalSymbol(Program externalProgram, ExternalLocation externalLoc) {

		// assume global symbol name if mangled name (same as original name) exists
		String label = externalLoc.getOriginalImportedName();
		SymbolPath symbolPath;
		if (label == null) {
			// use alternate symbol (may or may not be mangled)
			Symbol s = externalLoc.getSymbol();
			if (s.getSource() == SourceType.DEFAULT) {
				return null; // must rely on address for navigation
			}
			symbolPath = new SymbolPath(s, true);
		}
		else {
			symbolPath = new SymbolPath(label);
		}

		Symbol symbol = null;
		int count = 0;
		for (Symbol s : NamespaceUtils.getSymbols(symbolPath, externalProgram)) {
			symbol = s;
			++count;
			if (s.isExternalEntryPoint()) {
				return symbol;
			}
		}

		return count == 1 ? symbol : null;
	}

	private void createExternalAssociation(Program program, String extProgName) {
		int result = OptionDialog.showOptionDialog(null, "No Program Association",
			"The external program name \"" + extProgName +
				"\" is not associated with a Ghidra Program\n" +
				"Would you like to create an association?",
			"Create Association", OptionDialog.QUESTION_MESSAGE);
		if (result == OptionDialog.CANCEL_OPTION) {
			return;
		}
		final DataTreeDialog dialog = new DataTreeDialog(null,
			"Choose External Program (" + extProgName + ")", DataTreeDialog.OPEN);

		dialog.setSearchText(extProgName);
		dialog.setHelpLocation(new HelpLocation("ReferencesPlugin", "ChooseExternalProgram"));
		tool.showDialog(dialog);
		DomainFile domainFile = dialog.getDomainFile();
		if (dialog.wasCancelled() || domainFile == null) {
			return;
		}
		String pathName = domainFile.toString();
		ExternalManager externalManager = program.getExternalManager();
		String externalLibraryPath = externalManager.getExternalLibraryPath(extProgName);
		if (!pathName.equals(externalLibraryPath)) {
			Command cmd = new SetExternalNameCmd(extProgName, domainFile.getPathname());
			tool.execute(cmd, program);
		}
	}

	private Program findGoToProgram(Program currentProgram, Address address) {
		// we need to try and find a suitable program
		Program goToProgram = findProgramContaining(currentProgram, address);
		if (goToProgram == null) {
			return null;
		}

		return goToProgram;
	}

	private Program findProgramContaining(Program currentProgram, Address addr) {
		if (addr.isExternalAddress()) {
			return currentProgram; // only consider current program for external address
		}
		ProgramManager service = tool.getService(ProgramManager.class);
		if (service != null) {
			return service.getProgram(addr);
		}
		else if (currentProgram != null && currentProgram.getMemory().contains(addr)) {
			return currentProgram;
		}
		return null;
	}

}
