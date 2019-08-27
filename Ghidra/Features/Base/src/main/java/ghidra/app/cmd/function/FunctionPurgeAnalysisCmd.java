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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Command for analyzing the Stack; the command is run in the background.
 */
public class FunctionPurgeAnalysisCmd extends BackgroundCommand {
	private AddressSetView entryPoints;
	private Program program;
	private PrototypeModel[] nearFarModels = null;

	private static final int STDCALL_FAR = 0;
	private static final int CDECL_FAR = 1;
	private static final int STDCALL_NEAR = 2;
	private static final int CDECL_NEAR = 3;

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entries and address set indicating the entry points of functions that have 
	 * stacks to be analyzed.
	 */
	public FunctionPurgeAnalysisCmd(AddressSetView entries) {
		super("Compute Function Purge", true, true, false);
		entryPoints = entries;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		Processor processor = program.getLanguage().getProcessor();
		AddressSpace defaultSpace = program.getLanguage().getDefaultSpace();
		if (defaultSpace.getSize() > 32 ||
			!processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
			Msg.error(this,
				"Unsupported operation for language " + program.getLanguage().getLanguageID());
			return false;
		}
		if (defaultSpace instanceof SegmentedAddressSpace) {	// For 16-bit x86, prepare to establish near/fear calling convention models
			setupNearFarModels();
		}

		AddressSetView set = entryPoints;

		long maxCount = set.getNumAddresses();

		monitor.setMaximum(maxCount);
		monitor.setProgress(0);

		for (Function function : program.getFunctionManager().getFunctions(entryPoints, true)) {
			if (monitor.isCancelled()) {
				break;
			}

			set = set.subtract(
				new AddressSet(program, entryPoints.getMinAddress(), function.getEntryPoint()));
			monitor.setProgress(maxCount - set.getNumAddresses());

			monitor.setMessage("Purge " + function.getName());

			try {
				analyzeFunction(function, monitor);
			}
			catch (CancelledException e) {
				// do nothing
			}
		}
		if (monitor.isCancelled()) {
			setStatusMsg("Function Purge analysis cancelled");
			return false;
		}
		return true;
	}

	/**
	 * For x86 16-bit find the models stdcallnear, stdcallfar, cdeclnear, and cdeclfar so they can
	 * be applied at the same time function purge is set.
	 */
	private void setupNearFarModels() {
		int countModels = 0;
		nearFarModels = new PrototypeModel[4];
		nearFarModels[0] = null;
		nearFarModels[1] = null;
		nearFarModels[2] = null;
		nearFarModels[3] = null;
		PrototypeModel[] models = program.getCompilerSpec().getCallingConventions();
		for (PrototypeModel model : models) {
			if (model.isMerged()) {
				continue;
			}
			int pos = -1;
			if (model.getStackshift() == 4) {
				if (model.getExtrapop() == PrototypeModel.UNKNOWN_EXTRAPOP) {
					pos = STDCALL_FAR;
				}
				else if (model.getExtrapop() == 4) {
					pos = CDECL_FAR;
				}
			}
			else if (model.getStackshift() == 2) {
				if (model.getExtrapop() == PrototypeModel.UNKNOWN_EXTRAPOP) {
					pos = STDCALL_NEAR;
				}
				else if (model.getExtrapop() == 2) {
					pos = CDECL_NEAR;
				}
			}
			if (pos >= 0) {
				if (nearFarModels[pos] == null) {
					nearFarModels[pos] = model;
					countModels += 1;
				}
			}
		}
		if (countModels < 4) {
			Msg.warn(this,
				"FunctionPurgeAnalysis is missing full range of near/far prototype models");
		}
	}

	/**
	 * Analyze a function to build a stack frame based on stack references.
	 * @param function function to be analyzed
	 * @param monitor the task monitor that is checked to see if the command has
	 * been cancelled.
	 * @throws CancelledException if the user canceled this command
	 */
	private void analyzeFunction(Function function, TaskMonitor monitor) throws CancelledException {

		if (function == null) {
			return;
		}
		int purge = function.getStackPurgeSize();
		if (purge == -1 || purge > 128 || purge < -128) {
			Instruction purgeInstruction = locatePurgeInstruction(function, monitor);
			if (purgeInstruction != null) {
				purge = getPurgeValue(purgeInstruction);
				// if couldn't find it, don't set it!
				if (purge != -1) {
					function.setStackPurgeSize(purge);
				}
				setPrototypeModel(function, purgeInstruction);
			}
		}
	}

	private void setPrototypeModel(Function function, Instruction purgeInstruction) {
		if (nearFarModels == null) {
			return;
		}
		if (purgeInstruction.getFlowType().isCall()) {
			return;
		}
		if (function.getSignatureSource() != SourceType.DEFAULT) {
			return;
		}
		PrototypeModel model = null;
		try {
			byte val = purgeInstruction.getBytes()[0];
			if (val == (byte) 0xc3) {
				model = nearFarModels[CDECL_NEAR];
			}
			else if (val == (byte) 0xcb) {
				model = nearFarModels[CDECL_FAR];
			}
			else if (val == (byte) 0xc2) {
				model = nearFarModels[STDCALL_NEAR];
			}
			else if (val == (byte) 0xca) {
				model = nearFarModels[STDCALL_FAR];
			}
		}
		catch (MemoryAccessException e) {
			return;
		}
		if (model == null) {
			return;
		}
		try {
			function.setCallingConvention(model.getName());
		}
		catch (InvalidInputException e) {
			// Ignore if we can't change it
		}
	}

	private Instruction locatePurgeInstruction(Function func, TaskMonitor monitor) {
		AddressSetView body = func.getBody();
		Instruction purgeInstruction;

		purgeInstruction = findPurgeInstruction(body);
		if (purgeInstruction != null) {
			return purgeInstruction;
		}

		// look harder, maybe something wrong with body, compute with flow.
		body = CreateFunctionCmd.getFunctionBody(program, func.getEntryPoint(), monitor);
		return findPurgeInstruction(body);
	}

	/**
	 * Given a terminating instruction, discover the purge value encoded in it
	 * @param instr is the terminating instruction
	 * @return the purge value (or -1 if a value can't be found)
	 */
	private int getPurgeValue(Instruction instr) {
		if (instr.getFlowType().isCall()) {
			// is an override call-return, terminal/call
			// find a reference to a function, and take it's purge
			Reference[] referencesFrom = instr.getReferencesFrom();
			for (Reference reference : referencesFrom) {
				if (reference.getReferenceType().isFlow()) {
					Function functionAt =
						program.getFunctionManager().getFunctionAt(reference.getToAddress());
					// don't take the purge of a non-returning function
					if (functionAt != null && !functionAt.hasNoReturn()) {
						return functionAt.getStackPurgeSize();
					}
				}
			}
		}
		else {
			int tempPurge = 0;
			Scalar scalar = instr.getScalar(0);
			if (scalar != null) {
				tempPurge = (int) scalar.getSignedValue();
			}
			return tempPurge;
		}
		return -1;
	}

	/**
	 * Find a terminating instruction in the given set of addresses with a purge encoded in it.
	 * This routine prefers a RET instruction, but if none is available, it will use a
	 * terminating CALL.
	 * @param body is the set of addresses to look through
	 * @return a terminating instruction or null
	 */
	private Instruction findPurgeInstruction(AddressSetView body) {
		InstructionIterator iter = program.getListing().getInstructions(body, true);
		int count = 2048;
		Instruction backupPurge = null;
		while (iter.hasNext() && count > 0) {
			count--;
			Instruction instr = iter.next();

			FlowType ftype = instr.getFlowType();
			if (ftype.isTerminal()) {
				if (instr.getMnemonicString().compareToIgnoreCase("ret") == 0) {
					return instr;
				}
				else if (ftype.isCall()) {
					backupPurge = instr;	// Use as last resort, if we can't find RET
				}
			}
		}

		return backupPurge;
	}

}
