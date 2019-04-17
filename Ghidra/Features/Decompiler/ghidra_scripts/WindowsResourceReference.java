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
/*
 * Given certain Key windows API calls, tries to create references at the use of windows Resources.
 * This script uses the decompiler and the simplified Pcode AST to locate constant values passed to key
 * functions like LoadStringW, LoadIconW, etc...
 *
 * The guts of this script past the main could be used to analyze
 * constants passed to any function on any processor.
 * It is not restricted to windows.
 *
 * The assumption is made that default program analysis has already been run in order to retrieve
 * the best results from this script.
 * @category Windows
 */

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.*;

public class WindowsResourceReference extends GhidraScript {

	private static final String WINDOWS_RESOURCE_CHECKED_PROPERTYMAP = "WindowsResourceChecked";

	private DecompInterface decomplib;

	ArrayList<Address> routines = new ArrayList<>(); //Holds the address of found resource routines
	ArrayList<Integer> paramIndexes = new ArrayList<>(); //Holds the index of resource arguments on the stack
	ArrayList<ArrayList<PcodeOp>> defUseLists = new ArrayList<>();

	protected AddressSetPropertyMap alreadyDoneAddressSetPropertyMap;

	public AddressSetPropertyMap getOrCreatePropertyMap(Program program, String mapName) {
		if (alreadyDoneAddressSetPropertyMap != null) {
			return alreadyDoneAddressSetPropertyMap;
		}
		alreadyDoneAddressSetPropertyMap = program.getAddressSetPropertyMap(mapName);
		if (alreadyDoneAddressSetPropertyMap != null) {
			return alreadyDoneAddressSetPropertyMap;
		}

		try {
			alreadyDoneAddressSetPropertyMap = program.createAddressSetPropertyMap(mapName);
		}
		catch (DuplicateNameException e) {
			throw new AssertException(
				"Can't get DuplicateNameException since we tried to get it first");
		}

		return alreadyDoneAddressSetPropertyMap;
	}

	@Override
	public void run() throws Exception {

		// This code was added so that the analyzer (which calls a script) would not print script messages but if
		// run as a script it would still show output in the console.
		// It was also added to get the createBookmark option from the analyzer options.
		// The printScriptMsgs flag is checked every time the script tries to print.
		// The createBookmarks flag is checked every time the script tries to make a bookmark.
		// This also allows headless scripts to print if no args are passed but if they want no messages they
		// should pass the argument "false".
		// This also allows headless scripts to create bookmarks if no arguments are passed but if they want no
		// bookmarks they should pass the argument "false".

		// These are the default values if no arguments set them.
		boolean printScriptMsgs = true;
		boolean createBookmarks = true;

		// This gets the first argument if there are one or more arguments.
		String[] scriptArgs = getScriptArgs();
		if (scriptArgs.length >= 1) {
			if ("false".equals(scriptArgs[0])) {
				printScriptMsgs = false;
			}
		}

		// This gets the second argument if there is one.
		if (scriptArgs.length == 2) {
			if ("false".equals(scriptArgs[1])) {
				createBookmarks = false;
			}
		}

		AddressSetView restrictedSet = currentSelection;

		getOrCreatePropertyMap(currentProgram, WINDOWS_RESOURCE_CHECKED_PROPERTYMAP);

		// If this is the whole address space, look at everything
		// and ignore already done property
		if (restrictedSet == null || restrictedSet.isEmpty() ||
			restrictedSet.hasSameAddresses(currentProgram.getMemory())) {
			restrictedSet = null;
			alreadyDoneAddressSetPropertyMap.clear();
		}

		// If this is a partial address set, then ignore anywhere with a done it property

		try {
			decomplib = setUpDecompiler(currentProgram);
			if (decomplib == null) {
				if (printScriptMsgs) {
					println("Decompile Error: " + decomplib.getLastMessage());
				}
				return;
			}

			// Hold address and lookup constant value pairs for each resource lookup
			HashMap<Address, Long> constLocs;

			// Set of Resource name lookups. If unknown or variable Rsrc_ name
			// Rsrc_* wildcard allowed except when calling addResourceTableReferences()

			constLocs = associateResource("AfxMessageBox", 1, restrictedSet, printScriptMsgs);
			addResourceTableReferences(constLocs, "Rsrc_StringTable", printScriptMsgs,
				createBookmarks);

			constLocs = associateResource("CreateDialogParamA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Dialog", printScriptMsgs, createBookmarks);

			constLocs = associateResource("CreateDialogParamW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Dialog", printScriptMsgs, createBookmarks);

			constLocs = associateResource("DialogBoxParamA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Dialog", printScriptMsgs, createBookmarks);

			constLocs = associateResource("DialogBoxParamW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Dialog", printScriptMsgs, createBookmarks);

			constLocs = associateResource("FindResourceA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("FindResourceW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("FindResourceHandle", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadAcceleratorsA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Accelerator", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadAcceleratorsW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Accelerator", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadBitmapA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Bitmap", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadBitmapW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Bitmap", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadCursorA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadCursorW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadIconA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_GroupIcon", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadIconW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_GroupIcon", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadImageA", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadImageW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("RegLoadMUIStringW", 6, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_MUI", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadMenuA", 2, restrictedSet, printScriptMsgs);
			addResourceTableReferences(constLocs, "Rsrc_Menu", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadMenuW", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_Menu", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadRegTypeLib", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadStringA", 2, restrictedSet, printScriptMsgs);
			addResourceTableReferences(constLocs, "Rsrc_StringTable", printScriptMsgs,
				createBookmarks);

			constLocs = associateResource("LoadStringW", 2, restrictedSet, printScriptMsgs);
			addResourceTableReferences(constLocs, "Rsrc_StringTable", printScriptMsgs,
				createBookmarks);

			constLocs = associateResource("LoadTypeLib", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("LoadTypeLibEx", 2, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_*", printScriptMsgs, createBookmarks);

			constLocs = associateResource("PlaySoundW", 1, restrictedSet, printScriptMsgs);
			addResourceReferences(constLocs, "Rsrc_WAVE", printScriptMsgs, createBookmarks);

		}
		finally {
			decomplib.dispose();
		}
	}

	/**
	 * Associates a resource name with the name and ID of that resource
	 * @param resourceRoutine - Name of the resource routine
	 * @param paramIndex - Argument index of windows function call for resource lookup
	 * @param restrictedSet - Address space to use
	 * @param printScriptMsgs - if true, print output; if false, do not print any output;
	 * @return HashMap<Address, Long> map of addresses
	 */
	private HashMap<Address, Long> associateResource(String resourceRoutine, int paramIndex,
			AddressSetView restrictedSet, boolean printScriptMsgs) {

		HashMap<Address, Long> constUse = new HashMap<>();

		Symbol symbol = lookupRoutine(resourceRoutine, printScriptMsgs);
		if (symbol == null) {
			return constUse;
		}

		//Continue along if a symbol was found
		routines.add(symbol.getAddress());
		paramIndexes.add(paramIndex);
		ArrayList<PcodeOp> defUseList = new ArrayList<>();
		defUseLists.add(defUseList);

		HashSet<Address> doneRoutines = new HashSet<>();

		//Have a list of routines found based on symbol lookups
		while (routines.size() > 0) {
			// get the next routine to lookup
			Address addr = routines.remove(0);
			paramIndex = paramIndexes.remove(0);
			defUseList = defUseLists.remove(0);

			if (doneRoutines.contains(addr)) {
				continue;
			}

			doneRoutines.add(addr);

			// Get the list of references to this address
			ReferenceIterator referencesTo =
				currentProgram.getReferenceManager().getReferencesTo(addr);
			for (Reference reference : referencesTo) {
				if (monitor.isCancelled()) {
					break;
				}

				// Get the address of the function which is referenced
				Address refAddr = reference.getFromAddress();

				// if set is null, do no checks
				if (restrictedSet != null && !restrictedSet.contains(refAddr)) {
					continue;
				}

				// was this location already checked?
				if (alreadyDoneAddressSetPropertyMap != null) {
					if (alreadyDoneAddressSetPropertyMap.contains(refAddr)) {
						continue;
					}
					alreadyDoneAddressSetPropertyMap.add(refAddr, refAddr);
				}

				Function refFunc =
					currentProgram.getFunctionManager().getFunctionContaining(refAddr);

				if (refFunc == null) {
					refFunc = UndefinedFunction.findFunction(currentProgram, refAddr, monitor);
				}

				// this is an indirect reference, need to add the references to here.
				if (refFunc == null && reference.isExternalReference()) {
					routines.add(reference.getFromAddress());
					paramIndexes.add(paramIndex);
					defUseLists.add(new ArrayList<PcodeOp>());
					continue;
				}

				if (refFunc == null) {
					continue;
				}

				// decompile function
				// look for call to this function
				// display call
				@SuppressWarnings("unchecked")
				ArrayList<PcodeOp> localDefUseList = (ArrayList<PcodeOp>) defUseList.clone();

				monitor.setMessage(
					"Analyzing : " + refFunc.getName() + " for refs to " + resourceRoutine);

				analyzeFunction(constUse, decomplib, currentProgram, refFunc, refAddr, paramIndex,
					localDefUseList);
			}
		}

		return constUse;
	}

	/**
	 * Checks to see if the current resource routine is found in the
	 * programs symbol table.
	 * @param resourceRoutine - Name of the resource routine
	 * @param printScriptMsgs - if true, print output; if false, do not print any output;
	 * @return Symbol - found symbol based on resourceRoutine
	 */
	private Symbol lookupRoutine(String resourceRoutine, boolean printScriptMsgs) {

		Symbol foundSym = null;

		// Get the symbols that match the current resource routine
		SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(resourceRoutine);
		while (symbols.hasNext()) {
			//If a match is found get the function at the address of the found symbol
			foundSym = symbols.next();
			Function functionAt =
				currentProgram.getFunctionManager().getFunctionAt(foundSym.getAddress());
			if (functionAt != null) {
				return foundSym;
			}
		}

		if (foundSym != null && printScriptMsgs) {
			println("References to the " + resourceRoutine + " routine:");
		}
		return foundSym;
	}

	/**
	 * Analyze a functions references.
	 * Populates the address/value pairs of resource address and ID
	 * @param constUse - resource address/value pairs
	 */
	public void analyzeFunction(HashMap<Address, Long> constUse, DecompInterface decompiler,
			Program prog, Function f, Address refAddr, int paramIndex,
			ArrayList<PcodeOp> defUseList) {
		if (f == null) {
			return;
		}

		Instruction instr = prog.getListing().getInstructionAt(refAddr);
		if (instr == null) {
			return;
		}

		decompileFunction(f, decompiler);

		if (hfunction == null) {
			return; // failed to decompile
		}

		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps(refAddr);
		while (ops.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			PcodeOpAST pcodeOpAST = ops.next();
			if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {
				// get the second parameter
				Varnode parm = pcodeOpAST.getInput(paramIndex); // 1st param is the call dest
				if (parm == null) {
					return;
				}
				// see if it is a constant
				if (parm.isConstant()) {
					// then this is a resource id
					// lookup the resource and create a reference
					long value = parm.getOffset();
					// TODO: not so fast, if there is a defUseList, must apply it to get the real constant USED!
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(instr.getAddress(), value);
					}
					catch (InvalidInputException exc) {
						// don't worry about error
					}
				}
				else {
					followToParam(constUse, defUseList, hfunction, parm, null);
				}
				// if this is anything else, get the high variable to see if it can be traced back to a param
				// then repeat with any calls to this function at whatever the param is
			}
		}
	}

	/**
	 * Decompile the function
	 * @param f
	 * @param decompiler
	 * @return boolean - true if successful
	 */
	public boolean decompileFunction(Function f, DecompInterface decompiler) {
		// don't decompile the function again if it was the same as the last one
		if (f.getEntryPoint().equals(lastDecompiledFuncAddr)) {
			return true;
		}

		DecompileResults decompRes =
			decompiler.decompileFunction(f, decompiler.getOptions().getDefaultTimeout(), monitor);

		hfunction = decompRes.getHighFunction();

		if (hfunction == null) {
			return false;
		}

		lastDecompiledFuncAddr = f.getEntryPoint();

		return true;
	}

	/**
	 * Prints out the address of a found resource along with the name of
	 * the resource.
	 * @param constLocs - Address value pairs of the resource function
	 * @param resourceName - name of the resource
	 * @param printScriptMsgs - if true, print output; if false, do not print any output;
	 * @param createBookmarks - if true, create bookmarks where references are found; if false, do not create any bookmarks;
	 * @throws CancelledException
	 */
	private void addResourceReferences(HashMap<Address, Long> constLocs, String resourceName,
			boolean printScriptMsgs, boolean createBookmarks) throws CancelledException {
		Set<Address> keys;
		Iterator<Address> locIter;
		keys = constLocs.keySet();
		locIter = keys.iterator();
		while (locIter.hasNext()) {
			monitor.checkCanceled();

			Address loc = locIter.next();
			Instruction instr = currentProgram.getListing().getInstructionAt(loc);
			long rsrcID = constLocs.get(loc);
			Address rsrcAddr = findResource(resourceName + "_" + Long.toHexString(rsrcID), 0);

			if (rsrcAddr != null) {
				//Get the full symbol name including constant digits
				String symName = getSymbolAt(rsrcAddr).getName();
				//Match on the name without the constant  digit values
				String pattern = "([a-z]|[A-Z])*_?([a-z]|[A-Z])*(_[A-Z]+[a-z]+)?";
				Pattern r = Pattern.compile(pattern);
				Matcher m = r.matcher(symName);
				//Default to resourceName argument passed in unless found better match below
				String rsrcName = resourceName;
				if (m.find()) {
					rsrcName = m.group();
				}

				instr.addMnemonicReference(rsrcAddr, RefType.DATA, SourceType.ANALYSIS);
				if (createBookmarks) {
					currentProgram.getBookmarkManager().setBookmark(instr.getMinAddress(),
						BookmarkType.ANALYSIS, "WindowsResourceReference",
						"Added Resource Reference");
				}
				if (printScriptMsgs) {
					println("        " + instr.getMinAddress().toString() + " : Found " + rsrcName +
						" reference");
				}

			}
		}
	}

	/**
	 * Prints out the address of a found resource along with the name of
	 * the resource.
	 * @param constLocs - Address value pairs of the resource function
	 * @param tableName - Name of the resource table
	 * @param printScriptMsgs - if true, print output; if false, do not print any output;
	 * @param createBookmarks - if true, create bookmarks where references are found; if false, do not create any bookmarks;
	 * @throws CancelledException
	 */
	private void addResourceTableReferences(HashMap<Address, Long> constLocs, String tableName,
			boolean printScriptMsgs, boolean createBookmarks) throws CancelledException {
		Set<Address> keys;
		Iterator<Address> locIter;
		//Get the set of address locations which call the resource function
		keys = constLocs.keySet();
		locIter = keys.iterator();
		//Iterate though the set of address locations
		while (locIter.hasNext()) {
			monitor.checkCanceled();

			Address loc = locIter.next();
			Instruction instr = currentProgram.getListing().getInstructionAt(loc);
			Long rsrcID = constLocs.get(loc);
			Address rsrcAddr = null;
			if (rsrcID != null) {
				rsrcAddr = findResource(tableName, rsrcID);
			}

			if (rsrcAddr != null) {
				instr.addMnemonicReference(rsrcAddr, RefType.DATA, SourceType.ANALYSIS);
				if (createBookmarks) {
					currentProgram.getBookmarkManager().setBookmark(instr.getMinAddress(),
						BookmarkType.ANALYSIS, "WindowsResourceReference",
						"Added Resource Table Reference");
				}
				if (printScriptMsgs) {
					println("        " + instr.getMinAddress().toString() + " : Found " +
						tableName + " table reference " + rsrcID);
				}
			}
		}
	}

	/**
	 * Returns the address of the resource located in the program
	 * @param tableName - Name of the resource table
	 * @param rsrcID - ID of the resource to find
	 * @return Address of the found resource
	 * @throws CancelledException
	 */
	private Address findResource(String tableName, long rsrcID) throws CancelledException {

		SymbolIterator siter =
			currentProgram.getSymbolTable().getSymbolIterator(tableName + "*", true);

		if (!siter.hasNext()) {
			return null;
		}

		// Search each table
		while (siter.hasNext()) {
			monitor.checkCanceled();

			Symbol sym = siter.next();

			String symName = sym.getName();

			long curRsrcID = rsrcID;
			if (rsrcID != 0) {
				symName = symName.replaceAll(tableName + "_", "");
				//Find the specific table number of the resource
				String pattern = "_+[0-9]+";
				Pattern r = Pattern.compile(pattern);
				Matcher m = r.matcher(symName);
				String hexString = "";
				if (m.find()) {
					//Strip off the constant value to leave just the resource number
					hexString = symName.replaceAll(m.group(), "");
				}

				curRsrcID = Integer.parseInt(hexString, 16);
				curRsrcID = (curRsrcID - 1) * 0x10;
				curRsrcID = rsrcID - curRsrcID;
				if (curRsrcID > 0x10) {
					continue; // tables have 16 entries
				}
				if (curRsrcID < 0) {
					continue;
				}
			}

			Address currItemAddr = sym.getAddress();
			Data data = currentProgram.getListing().getDataAt(currItemAddr);

			while (curRsrcID > 0) {
				currItemAddr = data.getAddress();
				data = currentProgram.getListing().getDataAfter(currItemAddr);
				if (data == null || !data.isDefined()) {
					break;
				}
				curRsrcID--;
			}

			if (data == null) {
				continue;
			}

			if (curRsrcID == 0) {
				return data.getAddress();
			}

		}
		return null;
	}

	private long applyDefUseList(long value, ArrayList<PcodeOp> defUseList)
			throws InvalidInputException {

		if (defUseList == null || defUseList.size() <= 0) {
			return value;
		}
		Iterator<PcodeOp> iterator = defUseList.iterator();
		while (iterator.hasNext()) {
			PcodeOp pcodeOp = iterator.next();
			int opcode = pcodeOp.getOpcode();
			switch (opcode) {
				case PcodeOp.INT_AND:
					if (pcodeOp.getInput(0).isConstant()) {
						value = value & pcodeOp.getInput(0).getOffset();
					}
					else if (pcodeOp.getInput(1).isConstant()) {
						value = value & pcodeOp.getInput(1).getOffset();
					}
					else {
						throw new InvalidInputException(
							" Unhandled Pcode OP " + pcodeOp.toString());
					}
					break;
				default:
					throw new InvalidInputException(" Unhandled Pcode OP " + pcodeOp.toString());
			}
		}

		return value;
	}

	/**
	 * Finds the parameter passed into the resource function call
	 * @param constUse - Key value pairs of the resource function calls
	 * @param defUseList
	 * @param highFunction
	 * @param vnode
	 * @param doneSet
	 */
	private void followToParam(HashMap<Address, Long> constUse, ArrayList<PcodeOp> defUseList,
			HighFunction highFunction, Varnode vnode, HashSet<SequenceNumber> doneSet) {

		HighVariable hvar = vnode.getHigh();
		if (hvar instanceof HighParam) {
			Function function = highFunction.getFunction();
			routines.add(function.getEntryPoint());
			paramIndexes.add(((HighParam) hvar).getSlot() + 1);
			defUseLists.add(defUseList);
			return;
		}
		// follow back up through
		PcodeOp def = vnode.getDef();
		if (def == null) {
			return;
		}

		// have we done this vnode source already?
		Address vPCAddr = vnode.getPCAddress();
		SequenceNumber seqnum = def.getSeqnum();
		if (doneSet == null) {
			doneSet = new HashSet<>();
		}
		if (seqnum != null && doneSet.contains(seqnum)) {
			return;
		}
		doneSet.add(seqnum);

		int opcode = def.getOpcode();
		switch (opcode) {
			case PcodeOp.COPY:
				if (def.getInput(0).isConstant()) {
					long value = def.getInput(0).getOffset();
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(def.getOutput().getPCAddress(), value);
					}
					catch (InvalidInputException exc) {
						// ignore
					}
					return;
				}
				followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
				return;
			case PcodeOp.INT_ZEXT:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
				return;
			case PcodeOp.MULTIEQUAL:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
				@SuppressWarnings("unchecked")
				ArrayList<PcodeOp> splitUseList = (ArrayList<PcodeOp>) defUseList.clone();
				followToParam(constUse, splitUseList, highFunction, def.getInput(1), doneSet);
				return;
			case PcodeOp.CAST:
				// Cast will expose more Pcode, and could be attached to the same address!
				if (vPCAddr.equals(def.getInput(0).getPCAddress())) {
					doneSet.remove(vPCAddr);
				}
				followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
				return;
			case PcodeOp.INDIRECT:
				if (def.getOutput().getAddress().equals(def.getInput(0).getAddress())) {
					followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
					return;
				}
				break;
			case PcodeOp.INT_AND:
				if (def.getInput(1).isConstant()) {
					defUseList.add(0, def);
					followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
					return;
				}
				break;
			case PcodeOp.INT_ADD:
				if (def.getInput(1).isConstant()) {
					defUseList.add(0, def);
					followToParam(constUse, defUseList, highFunction, def.getInput(0), doneSet);
					return;
				}
				if (vnode.getHigh() instanceof HighParam) {
					// don't handle non-constants for now
				}
				break;
		}
		// println("     Lost IT! " + vnode.getPCAddress());
	}

	@SuppressWarnings("unused")
	private boolean isHexDigit(char charAt) {
		if (Character.isDigit(charAt)) {
			return true;
		}
		if ("abcdef".indexOf(charAt) >= 0) {
			return true;
		}
		if ("ABCDEF".indexOf(charAt) >= 0) {
			return true;
		}
		return false;
	}

	// Decompiler stuff

	private HighFunction hfunction = null;

	private Address lastDecompiledFuncAddr = null;

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompiler = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompiler.setOptions(options);

		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");

		decompiler.openProgram(program);

		return decompiler;
	}

}
