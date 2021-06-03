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

import java.io.IOException;

import ghidra.app.decompiler.*;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DecompilerParallelConventionAnalysisCmd extends BackgroundCommand {

	private static final String STD_NAMESPACE = "std";

	private Program program;

	private int decompilerTimeoutSecs;
	private DecompInterface decompiler;
	private Function function;

	public static DecompInterface createDecompilerInterface(Program program) throws IOException {
		DecompInterface newInterface = new DecompInterface();
		newInterface.toggleCCode(false);
		newInterface.toggleSyntaxTree(false); // only recovering the calling convention, no syntax tree needed
		newInterface.setSimplificationStyle("paramid");

		// Set decompiler up with default options for now and any grabbed from the program.
		// TODO: this should use the options from the tool somehow.
		//       unfortunately what is necessary is not here.
		DecompileOptions opts = new DecompileOptions();

		// turn off elimination of dead code, switch could be there.
		opts.setEliminateUnreachable(false);
		opts.grabFromProgram(program);
		newInterface.setOptions(opts);

		if (!newInterface.openProgram(program)) {
			throw new IOException("Unable to create decompiler for program: " + program);
		}

		return newInterface;
	}

	public DecompilerParallelConventionAnalysisCmd(Function func,
			DecompInterface decompilerInterface, int decompilerTimeoutSecs) {
		super("Identify Calling Convention", true, true, false);
		this.function = func;
		this.decompiler = decompilerInterface;
		this.decompilerTimeoutSecs = decompilerTimeoutSecs;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		try {
			monitor.checkCanceled();

			monitor.setMessage("Decompile " + function.getName());

			setStatusMsg(null);

			analyzeFunction(function, monitor);

			String errMsg = getStatusMsg();
			if (errMsg != null && errMsg.length() > 0) {
				return false;
			}
		}
		catch (CancelledException e) {
			// just drop out
		}
		catch (Exception e) {
			setStatusMsg(e.getMessage());
			return false;
		}
		return true;
	}

	/*
	 * The method indicates whether the function is in a block of code that is considered external or "glue"--meaning
	 *  that we don't want to analyze the code that might be there, yet we might have signatures for the function or
	 *  what it provides linkage to that we do not want to wipe.  We want to keep what is already there.
	 *  TODO: This implementation below, with hard-coded specific block names (other than EXTERNAL, which is created
	 *  by analysis) will need to be revisited.  Perhaps a flag will be set by the importer on the blocks that we should
	 *  ignore.
	 */
	private boolean funcIsExternalGlue(Function func) {
		String blockName = program.getMemory().getBlock(func.getEntryPoint()).getName();
		return (blockName.equals(MemoryBlock.EXTERNAL_BLOCK_NAME) || blockName.equals(".plt") ||
			blockName.equals("__stub_helper"));
	}

	private static boolean isInStdNamespace(Function function) {
		Namespace parentNamespace = function.getParentNamespace();
		return parentNamespace.getName().equals(STD_NAMESPACE) &&
			parentNamespace.getParentNamespace().getID() == Namespace.GLOBAL_NAMESPACE_ID;
	}

	private void analyzeFunction(Function f, TaskMonitor monitor) {

		// do some simple checks just in case
		if (f == null || f.isThunk() || isInStdNamespace(f)) {
			return;
		}

		// if custom storage already enabled or calling convention known, return
		if (f.hasCustomVariableStorage() ||
			!f.getCallingConventionName().equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
			return;
		}

		//We didn't "wipe" previous results of external functions, but we also do not want
		// to set new results.
		if (f.isExternal()) {
			return;
		}

		if (funcIsExternalGlue(f)) {
			return;
		}

		SourceType signatureSource = f.getSignatureSource();

		try {
			DecompileResults decompRes = null;
			if (monitor.isCancelled()) {
				return;
			}

			// reset the sourcetype so that no signature information goes to the decompiler
			//   we will set if back later.
			f.setSignatureSource(SourceType.DEFAULT);

			decompRes = this.decompiler.decompileFunction(f, decompilerTimeoutSecs, monitor);
			setStatusMsg(decompRes.getErrorMessage());

			if (monitor.isCancelled()) {
				return;
			}

			if (!decompRes.decompileCompleted()) {
				return;
			}

			HighFunction highFunction = decompRes.getHighFunction();
			String modelName = highFunction.getFunctionPrototype().getModelName();

			// TODO: Need to check the calling convention name
			//      what does decompiler return if it doesn't know convention, or guessed?
			if (!modelName.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
				signatureSource =
					updateCallingConvention(f, signatureSource, highFunction, modelName);
			}

			String errMsg = getStatusMsg();
			if (!monitor.isCancelled() && (errMsg != null && errMsg.length() != 0)) {
				Msg.debug(this, "  Failed to decompile function: " + f.getName() + " - " + errMsg);
			}
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				String errMsg = e.getMessage();
				if (errMsg == null) {
					errMsg = "Error decompiling function: " + e;
				}
				setStatusMsg(errMsg);
			}
		}
		finally {
			f.setSignatureSource(signatureSource);
		}
	}

	private SourceType updateCallingConvention(Function f, SourceType signatureSource,
			HighFunction highFunction, String modelName) throws InvalidInputException {
		// do the number of parameters disagree and decompiler says there is one more
		Namespace parentNamespace = f.getParentNamespace();
		if (f.getParameterCount() + 1 == highFunction.getFunctionPrototype().getNumParams()) {
			// does it have a namespace
			if (parentNamespace.getID() != Namespace.GLOBAL_NAMESPACE_ID &&
				// prevent accidental treatment of std namespace as class
				!parentNamespace.getName().equals(STD_NAMESPACE)) {
				//    does it have a this call convention that is the equivalent of the stdcall
				PrototypeModel callingConvention = program.getCompilerSpec().getCallingConvention(
					CompilerSpec.CALLING_CONVENTION_thiscall);
				if (callingConvention != null) {
					modelName = CompilerSpec.CALLING_CONVENTION_thiscall;
				}
			}
		}
		//   Then is __thiscall, create an object and new parameter if it doesn't have one yet.
		if (modelName.equals(CompilerSpec.CALLING_CONVENTION_stdcall) &&
			f.getStackPurgeSize() == 0 && f.getParameterCount() > 0) {
			// if has parameters, and there is no purge, it can't be a stdcall, change it to cdecl
			if (program.getLanguageID().getIdAsString().startsWith("x86:LE:32")) {
				modelName = CompilerSpec.CALLING_CONVENTION_cdecl;
				// it could be a this call...
			}
		}
		if (parentNamespace.getSymbol().getSymbolType() == SymbolType.NAMESPACE &&
			modelName.equals(CompilerSpec.CALLING_CONVENTION_thiscall)) {
			NamespaceUtils.convertNamespaceToClass(f.getParentNamespace());
		}
		f.setCallingConvention(modelName);
		if (signatureSource == SourceType.DEFAULT) {
			signatureSource = SourceType.ANALYSIS;
		}
		return signatureSource;
	}

}
