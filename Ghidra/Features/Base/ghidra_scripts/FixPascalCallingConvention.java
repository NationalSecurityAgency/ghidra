
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
// Script ensures that the PASCAL calling convention replaces STDCALL
// on function parameters and changes the stack reference for left-to-
// right stacking.  On the way, it also ensures that all Thunks are
// also converted.  This applies to Windows 16-bit apps.
//
//@category Repair
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FixPascalCallingConvention extends GhidraScript {

	private static final String PASCAL16FAR = "__pascal16far";

	private int cntFnsUpdated;
	private int cntParamsTotal;
	private int cntParamsReplaced;
	private int cntConvertionTotal;
	private int cntConvertionChanged;

	private List<String> warningMessages = new ArrayList<String>();

	@Override
	public void run() throws Exception {

		// reset for this run
		cntConvertionTotal = 0;
		cntConvertionChanged = 0;
		cntFnsUpdated = 0;
		cntParamsTotal = 0;
		cntParamsReplaced = 0;

		warningMessages.clear();

		if (currentProgram != null) {
			FunctionManager fnMgr = currentProgram.getFunctionManager();
			if (fnMgr == null) {
				return;
			}

			Iterator<Function> functions = null;

			// add function if pointing at its entry point ...
			if (isAddressAtFunctionStart(fnMgr, currentAddress)) {
				functions = fnMgr.getFunctionsOverlapping(new AddressSet(currentAddress));
			}

			// ... if not pointing at start of any function, try those currently selected
			// ...
			if (((functions == null) || !functions.hasNext()) && (currentSelection != null)) {
				functions = fnMgr.getFunctionsOverlapping(currentSelection);
			}

			// ... otherwise, choose them all
			if ((functions == null) || !functions.hasNext()) {
				functions = fnMgr.getFunctions(true);
			}

			// update details
			doRun(functions);

			// build popup information
			String buf = "Update " + cntConvertionChanged
					+ " calling convertions out of " + cntConvertionTotal + " to " + PASCAL16FAR
					+ ".\n\nUpdated " + cntFnsUpdated + " functions having " + cntParamsReplaced
					+ " parameters reversed out of " + cntParamsTotal + " parameters found.";
			if (!warningMessages.isEmpty()) {
				buf = buf + "\n\n" + String.join("\n\n", warningMessages);
			}

			popup(buf);

		}
	}

	/**
	 * @param fnMgr
	 * @param address
	 * @return
	 */
	private boolean isAddressAtFunctionStart(FunctionManager fnMgr, Address address) {
		boolean isAtStart = false;

		if ((address != null) && fnMgr.isInFunction(address)) {
			Function func = fnMgr.getFunctionContaining(address);
			isAtStart = ((func != null) && (func.getEntryPoint().compareTo(address) == 0));
		}

		return isAtStart;
	}

	/**
	 * Do for all function in program
	 */
	protected void doRun() {
		doRun(currentProgram.getFunctionManager().getFunctions(true));
	}

	/**
	 * @param functions
	 */
	private void doRun(Iterator<Function> functions) {
		while (functions.hasNext()) {
			if ((getMonitor() != null) && getMonitor().isCancelled()) {
				return;
			}

			doRun(functions.next());
		}
	}

	/**
	 * Do for individually identified function
	 * 
	 * @param func this function
	 * @throws InvalidInputException
	 */
	protected void doRun(Function func) {

		try {
			println("Before: " + func.getName() + ": " + func.getCallingConventionName()
					+ " and isExternal()=" + func.isExternal() + ", isThunk()=" + func.isThunk()
					+ getDescription(func));

			if (!func.getCallingConventionName().contains(GenericCallingConvention.pascal.name())
					&& (func.isExternal() || func.isThunk())) {
				try {
					++cntConvertionTotal;
					func.setCallingConvention(PASCAL16FAR);
					++cntConvertionChanged;
				} catch (InvalidInputException e) {
					warningMessages.add("Failed to change function '" + func.getName() + "' from "
							+ func.getCallingConventionName() + " to " + PASCAL16FAR + ".");
				}
			}

			// ensure External and Thunks were updated above!
			if (!func.getCallingConventionName().contains(GenericCallingConvention.pascal.name())) {
				return;
			}

			// only applicable to functions with 2 or more parameters
			int paramCnt = func.getParameterCount();
			if (paramCnt < 2) {
				return;
			}

			int firstLoc = func.getParameter(0).getStackOffset();
			int lastLoc = func.getParameter(paramCnt - 1).getStackOffset();
			// is already reversed
			if (lastLoc < firstLoc) {
				return;
			}

			++cntFnsUpdated;

			List<ParameterImpl> newParams = new ArrayList<>();

			for (int paramPos = paramCnt - 1; paramPos >= 0; --paramPos) {
				++cntParamsTotal;
				Parameter param = func.getParameter(paramPos);
				Varnode varnode = param.getLastStorageVarnode();
				Address addr = varnode.getAddress();
				if (!addr.isStackAddress()) {
					println("Param '" + param.getName() + "' isn't on the stack!");
					continue;
				}

				try {
					VariableStorage storage = new VariableStorage(currentProgram, firstLoc,
							varnode.getSize());
//				if (param instanceof ParameterDB) {
//					ParameterDB paramDB = (ParameterDB) param;
//					paramDB.setDynamicStorage(storage);
//				} else {
//					println("SCREWED");
//				}

					ParameterImpl pi = new ParameterImpl(param.getName(), param.getDataType(),
							storage, currentProgram);

					newParams.add(pi);

					firstLoc += varnode.getSize();

					func.removeParameter(paramPos); // Had to use!
				} catch (InvalidInputException e) {
					warningMessages.add("Unable to adjust storage location for function "
							+ func.getName() + ", parameter " + param.getName() + ".");
				}
			}

			SourceType source = func.getSignatureSource();
			StringBuffer buf = new StringBuffer();
			for (int paramPos = paramCnt - 1; paramPos >= 0; --paramPos) {
				ParameterImpl param = newParams.get(paramPos);
				try {
					buf.append(" ").append(param.getName()).append("[")
							.append(param.getLastStorageVarnode().toString()).append("]");
					func.setCustomVariableStorage(true); // TODO: should not need to be "Custom"!
					func.addParameter(param, source); // Had to use!

					++cntParamsReplaced;
				} catch (DuplicateNameException | InvalidInputException e) {
					warningMessages.add("Failed to reinsert function " + func.getName()
							+ " parameter " + param.getName() + ".");
				}
			}
			println("Params: " + buf.toString());

		} finally {
			println(" After: " + func.getName() + ":" + getDescription(func));
		}

//		The code below failed.
//		try {
//			func.replaceParameters(newParams, FunctionUpdateType.CUSTOM_STORAGE, true, func.getSignatureSource());
//			cntParamsReplaced += newParams.size();
//			++cntTotalFns;
//			println(" After: " + func.getName() + ":" + getDesc(func));
//		}
//		catch (InvalidInputException e) {
//			println("Failed to replace params for " + func.getName() + "@" + func.getEntryPoint() + ":" +
//					e.toString());
//			try {
//				func.replaceParameters(newParams, FunctionUpdateType.CUSTOM_STORAGE, true, func.getSignatureSource());
//			}
//			catch (InvalidInputException e2) {
//				println("Failed to replace params for " + func.getName() + "@" + func.getEntryPoint() + ":" +
//						e2.toString());
//			}
//		}
	}

	/**
	 * @param f Function object
	 * @return string to print out
	 */
	private static String getDescription(Function f) {
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < f.getParameters().length; i++) {
			Parameter p = f.getParameter(i);
			s.append(" ").append(p.getName()).append("[")
					.append(p.getLastStorageVarnode().toString()).append("]");
		}
		return s.toString();
	}

}
