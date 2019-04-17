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
//  Identify and mark string parameters for functions by examining all references to defined strings
//   to see which functions they are passed into.  If a defined string is passed into
//   a function, then that parameter must be a pointer to a string.
//
//   WARNING: This script does not attempt to discover var-arg situations.  It should be changed to do so.
//
//   The engine for the script is the decompiler.
//   
//   The guts of this script past the main could be used to analyze
//   constants passed to any function on any processor.
//   It is not restricted to windows.
//
//@category Analysis

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

import java.util.*;

public class StringParameterPropagator extends GhidraScript {

	// TODO!! Error handling needs a lot of work !!

	private DecompInterface decomplib;

	class FuncInfo {
		int minParamSeen = 256;
		int maxParamSeen = 0;
		BitSet paramsNoted = new BitSet();
		DataType dt = null;
		boolean conflictingDT = false;

		// set that a given parameter had the attribute being tracked
		void setParamSeen(int paramIndex) {
			paramsNoted.set(paramIndex);
		}

		void setDataTypeSeen(DataType dt) {
			if (conflictingDT) {
				return;
			}
			if (dt == null) {
				return;
			}
			if (this.dt != null && !this.dt.isEquivalent(dt)) {
				conflictingDT = true;
				return;
			}
			this.dt = dt;
		}

		// record the number of parameters a particular function has
		void setNumParamsSeen(int numParams) {
			if (numParams < minParamSeen) {
				minParamSeen = numParams;
			}
			if (numParams > maxParamSeen) {
				maxParamSeen = numParams;
			}
		}

		// true if all functions had the same number of parameters
		boolean numParamsAgree() {
			return (maxParamSeen == minParamSeen);
		}

		int getMinParamsSeen() {
			return minParamSeen;
		}

		DataType getDataType() {
			if (conflictingDT) {
				return DataType.DEFAULT;
			}
			return dt;
		}

		// get a list of parameter indexes that had the attribute being tracked
		ArrayList<Integer> getParamsSeen() {
			ArrayList<Integer> list = new ArrayList<Integer>();
			for (int i = 0; i <= maxParamSeen; i++) {
				if (paramsNoted.get(i)) {
					list.add(i);
				}
			}
			return list;
		}

		public int getMaxParamsSeen() {
			return maxParamSeen;
		}
	}

	@Override
	public void run() throws Exception {
		try {
			decomplib = setUpDecompiler(currentProgram);

			if (!decomplib.openProgram(currentProgram)) {
				println("Decompile Error: " + decomplib.getLastMessage());
				return;
			}

			HashSet<Address> stringLocationSet = new HashSet<Address>();
			HashSet<Address> callingFuncLocationSet = new HashSet<Address>();

			monitor.setMessage("Finding References to Data");
			long start = System.currentTimeMillis();
			// for each string data type defined
			collectStringDataReferenceLocations(stringLocationSet, callingFuncLocationSet);
//	    	collectDataRefenceLocations(stringLocationSet, callingFuncLocationSet);
//	    	collectSymbolDataRefenceLocations(stringLocationSet, callingFuncLocationSet);
			long end = System.currentTimeMillis();
			println("Initial search took : " + (end - start) / 1000 + " seconds");

			// iterate over functions
			HashMap<Address, FuncInfo> funcParamMap = new HashMap<Address, FuncInfo>();
			//Iterator<Address> callingFuncIter = callingFuncLocationSet.iterator();
			while ((callingFuncLocationSet.size() > 0) && !monitor.isCancelled()) {
				Iterator<Address> callingFuncIter = callingFuncLocationSet.iterator();
				if (!callingFuncIter.hasNext()) {
					break;
				}
				Address entry = callingFuncIter.next();
				callingFuncIter.remove();

				Function func = currentProgram.getFunctionManager().getFunctionAt(entry);
				if (func == null) {
					continue;
				}

				monitor.setMessage("Analyzing calls in " + func.getName());

				//    look at each call
				//    if param points to a string data type.
				//        put on HashMap of function -> param#

				analyzeFunction(funcParamMap, decomplib, currentProgram, func, stringLocationSet);
			}

			// iterate over HashMap of functions
			HashSet<Address> doneItSet = new HashSet<Address>();
			Iterator<Address> entryIter = funcParamMap.keySet().iterator();
			while (entryIter.hasNext() && !monitor.isCancelled()) {
				Address entry = entryIter.next();
				FuncInfo funcInfo = funcParamMap.get(entry);

				// TODO: Need to detect Var-args situation.
				//       maybe record the number of params the function had last time, versus now?
				if (doneItSet.contains(entry)) {
					continue;
				}
				doneItSet.add(entry);

				Function calledFunc = getFunctionAt(entry);

				if (calledFunc == null) {
					calledFunc = createFunction(entry, null);
				}
				if (calledFunc == null || !decompileFunction(calledFunc, decomplib)) {
					continue;
				}

				//    if Param not already char *
				//        store params to database
				//        set param# to char *

				int minParams = funcInfo.getMinParamsSeen();
				int maxParams = funcInfo.getMaxParamsSeen();
				boolean couldBeVararg = !funcInfo.numParamsAgree();
				if (!funcInfo.numParamsAgree()) {
					currentProgram.getBookmarkManager().setBookmark(calledFunc.getEntryPoint(),
						BookmarkType.NOTE, this.getClass().getName(),
						"Number of parameters disagree min: " + minParams + " max: " + maxParams);

					println("WARNING : Number of params disagree for " + calledFunc.getName() +
						" @ " + entry);
					if (minParams > 6) {
						continue;
					}
				}

				ArrayList<Integer> paramsSeen = funcInfo.getParamsSeen();
				while (paramsSeen.size() > 0) {
					int paramIndex = paramsSeen.remove(0);
					if (paramIndex > minParams) {
						println("WARNING: at " + calledFunc.getName() + ", Couldn't apply param " +
							paramIndex);
						continue;
					}
					DataType dt = new PointerDataType(funcInfo.getDataType());
					@SuppressWarnings("unused")
					boolean mustRedo =
						checkParams(calledFunc, dt, paramIndex, minParams, couldBeVararg);
				}

				// if the signature changes, must redo the function
				//    so get it off the done-list, and put it back on list of functions to look at
//				if (mustRedo) {
//					doneItSet.remove(entry);
//					// redo the function that called this function, because this function changed its parameters
//					redoAddress = func.getEntryPoint();
//					break;
//				}
			}

			end = System.currentTimeMillis();
			println("Total took : " + (end - start) / 1000 + " seconds");
		}
		finally {
			if (decomplib != null) {
				decomplib.dispose();
			}
		}
	}

	@SuppressWarnings("unused")
	private void collectSymbolDataRefenceLocations(HashSet<Address> dataItemLocationSet,
			HashSet<Address> referringFuncLocationSet) {
		SymbolTable symtab = currentProgram.getSymbolTable();
		SymbolIterator symiter = symtab.getAllSymbols(true);
		int count = 0;
		while (symiter.hasNext() && !monitor.isCancelled()) {
			Symbol sym = symiter.next();
			if (!sym.hasReferences()) {
				continue;
			}
			Address addr = sym.getAddress();

			if (count == 0) {
				monitor.setMessage("looking at : " + addr);
			}
			count = (count + 1) % 1024;

			Data data = currentProgram.getListing().getDataAt(addr);
			if (data == null) {
				Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
				if (func == null) {
					// no function, no data, get out
					continue;
				}
			}
			Reference[] refs = sym.getReferences(null);
			for (int i = 0; i < refs.length && !monitor.isCancelled(); i++) {
				Reference ref = refs[i];
				// don't want flow references
				if (ref.getReferenceType().isFlow()) {
					continue;
				}
				// don't want reference to stack, although maybe we do...
				if (!ref.isMemoryReference()) {
					continue;
				}
				dataItemLocationSet.add(ref.getToAddress());

				Function func =
					currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (func == null) {
					continue;
				}
				referringFuncLocationSet.add(func.getEntryPoint());
			}
		}
	}

	private void collectStringDataReferenceLocations(HashSet<Address> stringLocationSet,
			HashSet<Address> referringFuncLocationSet) {
		DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
		while (dataIter.hasNext() && !monitor.isCancelled()) {
			Data data = dataIter.next();
			// put string dt in addr set
			DataType dt = data.getDataType();
			if (!(dt instanceof StringDataType || dt instanceof TerminatedStringDataType ||
				dt instanceof UnicodeDataType || dt instanceof TerminatedUnicodeDataType)) {
				continue;
			}
			stringLocationSet.add(data.getAddress());
			ReferenceIterator refIter =
				currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
			//     find functions referencing the string
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				Function func =
					currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (func == null) {
					Data rData = currentProgram.getListing().getDefinedDataAt(ref.getFromAddress());
					if (rData == null) {
						continue;
					}
					if (rData.isPointer()) {
						ReferenceIterator dataRefIter = rData.getReferenceIteratorTo();
						while (dataRefIter.hasNext()) {
							Reference dataRef = dataRefIter.next();
							func =
								currentProgram.getFunctionManager().getFunctionContaining(
									dataRef.getFromAddress());
							if (func == null) {
								continue;
							}
							referringFuncLocationSet.add(func.getEntryPoint());
						}
					}
					continue;
				}
				referringFuncLocationSet.add(func.getEntryPoint());
			}
		}
	}

	@SuppressWarnings("unused")
	private void collectDataRefenceLocations(HashSet<Address> dataItemLocationSet,
			HashSet<Address> referringFuncLocationSet) {
		int count = 0;
		ReferenceIterator iter =
			currentProgram.getReferenceManager().getReferenceIterator(
				currentProgram.getMinAddress());
		while (iter.hasNext() && !monitor.isCancelled()) {
			Reference ref = iter.next();

			if (count == 0) {
				monitor.setMessage("looking at : " + ref.getToAddress());
			}
			count = (count + 1) % 1024;

			// don't want flow references
			if (ref.getReferenceType().isFlow()) {
				continue;
			}
			// don't want reference to stack, although maybe we do...
			if (!ref.isMemoryReference()) {
				continue;
			}

			dataItemLocationSet.add(ref.getToAddress());

			Function func =
				currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
			if (func == null) {
				continue;
			}

			referringFuncLocationSet.add(func.getEntryPoint());
		}
	}

	private void markStringParam(HashMap<Address, FuncInfo> constUse, Address refAddr,
			Address entry, int paramIndex, int numParams) {
		FuncInfo curVal = constUse.get(entry);

		if (curVal == null) {
			curVal = new FuncInfo();
			constUse.put(entry, curVal);
		}
		curVal.setNumParamsSeen(numParams); // saw this many params
		curVal.setParamSeen(paramIndex);    // saw string at param x

		Data data = currentProgram.getListing().getDefinedDataAt(refAddr);
		DataType dt = null;
		String name = "Ptr";
		if (data != null) {
			dt = data.getDataType();
			name = dt.getName();
		}
		curVal.setDataTypeSeen(dt);

		println("found " + name + " param for " + entry + " param " + paramIndex);
	}

	@SuppressWarnings("deprecation")
	private boolean checkParams(Function func, DataType dt, int paramIndex, int minParams,
			boolean couldBeVararg) {
		if (func == null) {
			return false;
		}

		PrototypeModel initialConvention = func.getCallingConvention();
		if (!func.hasVarArgs()) {
			fixupParams(func, minParams, couldBeVararg);
		}

		// make sure prototype of called function didn't change!
		PrototypeModel convention = func.getCallingConvention();
		if (initialConvention == null && convention != null) {
			return true;
		}
		if (convention == null) {
			convention = currentProgram.getCompilerSpec().getDefaultCallingConvention();
		}
		if (initialConvention != null && !convention.getName().equals(initialConvention.getName())) {
			return true;
		}

		// don't create strings past varargs
		if (func.hasVarArgs() && paramIndex >= func.getParameterCount()) {
			return false;
		}

		Parameter param = func.getParameter(paramIndex);
		if (param != null && param.getDataType() instanceof PointerDataType) {
			return false;
		}

		if (param == null) {
			if (convention == null) {
				return false;
			}
			VariableStorage storage =
				convention.getArgLocation(paramIndex, func.getParameters(), dt, currentProgram);
			if (storage.isUnassignedStorage()) {
				return false;
			}
			try {
				param = new ParameterImpl(null, dt, storage, func.getProgram());
				// TODO: Fix deprecated method call
				param = func.addParameter(param, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (InvalidInputException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		if (param == null) {
			return false;
		}
		currentProgram.getBookmarkManager().setBookmark(func.getEntryPoint(), BookmarkType.NOTE,
			this.getClass().getName(), "Created " + dt.getName() + " parameter");
		return false;
	}

	@SuppressWarnings("deprecation")
	private void fixupParams(Function f, int minParams, boolean couldBeVararg) {
		if (f == null) {
			return;
		}
		if (couldBeVararg) {
			for (int i = f.getParameterCount(); i > minParams && i > 0; i--) {
				f.removeParameter(i - 1);
			}
			f.setVarArgs(true);
		}
		// must make number of parameters agree with function, because will be storing off a structure ptr
		LocalSymbolMap vmap = hfunction.getLocalSymbolMap();
		int numParams = vmap.getNumParams();
		if (f.getParameterCount() == numParams && f.getParameterCount() == minParams) {
			return;
		}
		if (minParams == numParams) {
			try {
				HighFunctionDBUtil.commitParamsToDatabase(hfunction, true, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected exception", e);
			}
			catch (InvalidInputException e) {
				println("  ** problem at \n" + e.getMessage());
			}
			return;
		}

		// make sure prototype of called function didn't change!
		PrototypeModel convention = f.getCallingConvention();
		if (convention == null) {
			convention = currentProgram.getCompilerSpec().getDefaultCallingConvention();
		}

		for (int i = 1; i <= minParams; i++) {
			if (i < f.getParameterCount()) {
				continue;
			}
			VariableStorage storage =
				convention.getArgLocation(i - 1, f.getParameters(), DataType.DEFAULT,
					currentProgram);
			if (storage.isUnassignedStorage()) {
				break;
			}
			try {
				Parameter param =
					new ParameterImpl(null, DataType.DEFAULT, storage, f.getProgram());
				// TODO: Fix deprecated method call
				f.addParameter(param, SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {
				println("  ** problem at \n" + e.getMessage());
			}
			catch (InvalidInputException e) {
				println("  ** problem at \n" + e.getMessage());
			}
		}

	}

	/**
	 * Analyze a functions references
	 * @param constUse 
	 */
	public void analyzeFunction(HashMap<Address, FuncInfo> constUse,
			DecompInterface decompInterface, Program prog, Function f,
			HashSet<Address> stringLocationSet) {
		if (f == null) {
			return;
		}

		if (!decompileFunction(f, decompInterface)) {
			return;
		}
		Address entry = f.getEntryPoint();

		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			// System.out.println(pcodeOpAST);
			if (pcodeOpAST.getOpcode() != PcodeOp.CALL) {
				continue;
			}
			Varnode calledFunc = pcodeOpAST.getInput(0);

			if (calledFunc == null || !calledFunc.isAddress()) {
				continue;
			}
			Address calledFuncAddr = calledFunc.getAddress();

			// rifle through parameters
			int numParams = pcodeOpAST.getNumInputs();
			for (int i = 1; i < numParams; i++) {
				Varnode parm = pcodeOpAST.getInput(i);  // 1st param is the call dest
				if (parm == null) {
					continue;
				}

				// follow back to a const if possible
				ArrayList<PcodeOp> localDefUseList = new ArrayList<PcodeOp>();

				// check out the constUse list to see if we fished out a constant.  Don't follow out of function
				// see if it is a constant
				if (parm.isConstant()) {
					// then this is a resource id
					// lookup the resource and create a reference
					long value = parm.getOffset();
					// TODO: not so fast, if there is a defUseList, must apply it to get the real constant USED!
					try {
						value = applyDefUseList(value, localDefUseList);
						// constUse.put(calledFuncAddr, i);
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}

					long mask =
						0xffffffffffffffffL >>> ((8 - entry.getAddressSpace().getPointerSize()) * 8);
					Address possibleAddr = entry.getNewAddress(mask & value);
					if (stringLocationSet.contains(possibleAddr)) {
						markStringParam(constUse, possibleAddr, calledFuncAddr, i - 1,
							numParams - 1);
					}
				}
				if (parm.isAddress()) {
					if (stringLocationSet.contains(parm.getAddress())) {
						markStringParam(constUse, parm.getAddress(), calledFuncAddr, i - 1,
							numParams - 1);
					}
				}
			}
		}
	}

	private long applyDefUseList(long value, ArrayList<PcodeOp> defUseList)
			throws InvalidInputException {
		if (defUseList.size() > 0)
			throw new InvalidInputException();
		return value;
	}

	// Decompiler stuff

	private HighFunction hfunction = null;

	//private ClangTokenGroup docroot = null;

	private Address lastDecompiledFuncAddr = null;

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

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
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public boolean decompileFunction(Function f, DecompInterface decompInterface) {
		// don't decompile the function again if it was the same as the last one
		//
		if (f.getEntryPoint().equals(lastDecompiledFuncAddr))
			return true;

		try {
			DecompileResults decompRes =
				decompInterface.decompileFunction(f,
					decompInterface.getOptions().getDefaultTimeout(), monitor);

			hfunction = decompRes.getHighFunction();
		}
		catch (Exception exc) {
			exc.printStackTrace();
			return false;
		}

		if (hfunction == null)
			return false;

		lastDecompiledFuncAddr = f.getEntryPoint();

		return true;
	}
}
