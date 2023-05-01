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
package ghidra.app.plugin.core.debug.stack;

import java.io.IOException;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.*;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * The interpreter of p-code ops in the domain of {@link Sym}
 * 
 * <p>
 * This is used for static analysis by executing specific basic blocks. As such, it should never be
 * expected to interpret a conditional jump. (TODO: This rule might be violated if a fall-through
 * instruction has internal conditional branches.... To fix would require breaking the p-code down
 * into basic blocks.) We also do not want it to descend into subroutines. Thus, we must treat calls
 * differently. Most of the implementation of this class is to attend to function calls, especially,
 * indirect calls. For direct calls, it attempts to find the function in the same program (possibly
 * in its import table) and derive the resulting stack effects from the database. Failing that, it
 * issues warnings and makes reasonable assumptions. For indirect calls, it attempts to decompile
 * the caller and examines the call site. If the target's type is known (presumably a function
 * pointer), then the stack effects are derived from the signature and its calling convention. If
 * not, then it examines the inputs and output (if applicable) to derive a signature and then
 * figures the stack effects. In many cases, the stack adjustment is defined solely by the compiler,
 * but for the {@code __stdcall} convention prominent in 32-bit x86 binaries for Windows, the input
 * parameters must also be examined.
 */
class SymPcodeExecutor extends PcodeExecutor<Sym> {

	/**
	 * Construct an executor for performing stack unwind analysis of a given program
	 * 
	 * @param program the program to analyze
	 * @param state the symbolic state
	 * @param reason a reason to give when reading state
	 * @param warnings a place to emit warnings
	 * @param monitor a monitor for analysis, usually decompilation
	 * @return the executor
	 */
	public static SymPcodeExecutor forProgram(Program program, SymPcodeExecutorState state,
			Reason reason, Set<StackUnwindWarning> warnings, TaskMonitor monitor) {
		CompilerSpec cSpec = program.getCompilerSpec();
		SleighLanguage language = (SleighLanguage) cSpec.getLanguage();
		SymPcodeArithmetic arithmetic = new SymPcodeArithmetic(cSpec);
		return new SymPcodeExecutor(program, cSpec, language, arithmetic, state, reason, warnings,
			monitor);
	}

	private final Program program;
	private final Register sp;
	private final Set<StackUnwindWarning> warnings;
	private final TaskMonitor monitor;

	private final DecompInterface decomp = new DecompInterface();
	// TODO: This could perhaps be moved into AnalysisForPC?
	// Meh, as it is, it should only have at most 1 entry
	private final Map<Function, HighFunction> decompCache = new HashMap<>();

	public SymPcodeExecutor(Program program, CompilerSpec cSpec, SleighLanguage language,
			SymPcodeArithmetic arithmetic, SymPcodeExecutorState state, Reason reason,
			Set<StackUnwindWarning> warnings, TaskMonitor monitor) {
		super(language, arithmetic, state, reason);
		this.program = program;
		this.sp = cSpec.getStackPointer();
		this.warnings = warnings;
		this.monitor = monitor;
	}

	@Override
	public void executeCallother(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<Sym> library) {
		// Do nothing
		// TODO: Is there a way to know if a userop affects the stack?
	}

	/**
	 * Attempt to figure the stack depth change for a given function
	 * 
	 * @param function the function whose depth change to compute
	 * @param warnings a place to emit warnings
	 * @return the depth change, i.e., change to SP
	 */
	public static int computeStackChange(Function function, Set<StackUnwindWarning> warnings) {
		// TODO: How does this work for varargs functions with stack parameters?
		// Seems not much heed is given to signature or call site
		// Analyzers set stackPurgeSize, but still, that's on the function, not the site.
		// NOTE: It seems stdcall doesn't support varargs, so this issue should not arise.
		PrototypeModel convention = function.getCallingConvention();
		if (convention == null) {
			if (warnings != null) {
				warnings.add(new UnspecifiedConventionStackUnwindWarning(function));
			}
			convention = function.getProgram().getCompilerSpec().getDefaultCallingConvention();
		}
		int extrapop = convention.getExtrapop();
		if (extrapop == PrototypeModel.UNKNOWN_EXTRAPOP) {
			throw new PcodeExecutionException("Cannot get stack change for function " + function);
		}
		if (function.isStackPurgeSizeValid()) {
			return extrapop + function.getStackPurgeSize();
		}
		if (warnings != null) {
			warnings.add(new UnknownPurgeStackUnwindWarning(function));
		}
		return extrapop;
	}

	/**
	 * Attempt to figure the stack depth change for a given function
	 * 
	 * @param callee the function being called
	 * @return the depth change, i.e., change to SP
	 */
	public int computeStackChange(Function callee) {
		return computeStackChange(callee, warnings);
	}

	@Override
	public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<Sym> library) {
		Address target = op.getInput(0).getAddress();
		Function callee = program.getFunctionManager().getFunctionAt(target);
		if (callee == null) {
			throw new PcodeExecutionException("Callee at " + target + " is not a function.", frame);
		}
		String fixupName = callee.getCallFixup();
		if (fixupName != null && !"".equals(fixupName)) {
			PcodeProgram snippet;
			try {
				snippet = PcodeProgram.fromInject(program, fixupName, InjectPayload.CALLFIXUP_TYPE);
				execute(snippet, library);
			}
			catch (MemoryAccessException | UnknownInstructionException | NotFoundException
					| IOException e) {
				throw new PcodeExecutionException("Issue executing callee fixup: ", e);
			}
			return;
		}
		int change = computeStackChange(callee);
		adjustStack(change);
	}

	/**
	 * Decompile the given low p-code op to its high p-code op
	 * 
	 * <p>
	 * Note this is not decompilation of the op in isolation. Decompilation usually requires a
	 * complete function for context. This will decompile the full containing function then examine
	 * the resulting high p-code ops at the same address as the given op, which are presumably those
	 * derived from it. It then seeks a unique call (or call indirect) op.
	 * 
	 * @param op the low p-code op
	 * @return the high p-code op
	 */
	protected PcodeOpAST getHighCallOp(PcodeOp op) {
		Address callSite = op.getSeqnum().getTarget();
		Function caller = program.getFunctionManager().getFunctionContaining(callSite);

		HighFunction hfunc = decompCache.computeIfAbsent(caller, c -> {
			decomp.openProgram(program);
			DecompileResults results = decomp.decompileFunction(c, 3, monitor);
			return results.getHighFunction();
		});

		List<PcodeOpAST> found = new ArrayList<>();
		Iterator<PcodeOpAST> oit = hfunc.getPcodeOps(callSite);
		while (oit.hasNext()) {
			PcodeOpAST hop = oit.next();
			if (hop.getOpcode() == PcodeOp.CALLIND || hop.getOpcode() == PcodeOp.CALL) {
				found.add(hop);
			}
		}
		if (found.size() == 1) {
			return found.get(0);
		}
		if (found.size() > 1) {
			warnings.add(new MultipleHighCallsStackUnwindWarning(found));
			return found.get(0);
		}
		warnings.add(new NoHighCallsStackUnwindWarning(op));
		return null;
	}

	/**
	 * Derive the signature from the call op's target (first input) type
	 * 
	 * @param op the call or call indirect op
	 * @return the signature if successful, or null
	 */
	protected FunctionSignature getSignatureFromTargetPointerType(PcodeOpAST op) {
		VarnodeAST target = (VarnodeAST) op.getInput(0);
		DataType dataType = target.getHigh().getDataType();
		if (!(dataType instanceof Pointer ptrType)) {
			warnings.add(new UnexpectedTargetTypeStackUnwindWarning(dataType));
			return null;
		}
		if (!(ptrType.getDataType() instanceof FunctionSignature sigType)) {
			warnings.add(new UnexpectedTargetTypeStackUnwindWarning(dataType));
			return null;
		}
		return sigType;
	}

	/**
	 * Derive the signature from the call op's parameters (second and on inputs) types
	 * 
	 * @param op the call or call indirect op
	 * @return the signature if successful, or null
	 */
	protected FunctionSignature getSignatureFromContextAtCallSite(PcodeOpAST op) {
		FunctionDefinitionDataType sig = new FunctionDefinitionDataType("__indirect");
		sig.setReturnType(op.getOutput().getHigh().getDataType());
		// input 0 is the target, so drop it.
		int numInputs = op.getNumInputs();
		Parameter[] params = new Parameter[numInputs - 1];
		ParameterDefinition[] arguments = new ParameterDefinition[numInputs - 1];
		for (int i = 1; i < numInputs; i++) {
			Varnode input = op.getInput(i);
			HighVariable highVar = input.getHigh();
			try {
				/**
				 * NOTE: Not specifying storage, since: 1) It's not germane to the function
				 * signature, and 2) It may require chasing use-def chains through uniques.
				 */
				params[i - 1] = new ParameterImpl("param_" + i, highVar.getDataType(),
					/*new VariableStorage(program, input),*/ program);
			}
			catch (InvalidInputException e) {
				throw new AssertionError(e);
			}
			arguments[i - 1] = new ParameterDefinitionImpl("param_" + i,
				input.getHigh().getDataType(), "generated");
		}
		sig.setArguments(arguments);
		sig.setComment("generated");

		// TODO: Does the decompiler communicate the inferred calling convention?
		try {
			PrototypeModel convention = program.getCompilerSpec().findBestCallingConvention(params);
			sig.setCallingConvention(convention.getName());
		}
		catch (SleighException | InvalidInputException e) {
			// Whatever, just leave sig at "unknown"
		}
		return sig;
	}

	/**
	 * Derive the function signature for an indirect call
	 * 
	 * <p>
	 * This first examines the target's type. Failing that, it examines the parameter and return
	 * types at the call site.
	 * 
	 * @param lowOp the low p-code op
	 * @return the signature if successful, or null
	 */
	protected FunctionSignature getSignatureOfIndirectCall(PcodeOp lowOp) {
		PcodeOpAST callOp = getHighCallOp(lowOp);
		if (callOp == null) {
			return null;
		}
		FunctionSignature signature = getSignatureFromTargetPointerType(callOp);
		if (signature != null) {
			return signature;
		}
		signature = getSignatureFromContextAtCallSite(callOp);
		if (signature != null) {
			return signature;
		}
		warnings.add(new CouldNotRecoverSignatureStackUnwindWarning(callOp));
		return null;
	}

	/**
	 * Assuming the convention represents {@code __stdcall} determine the stack depth change for the
	 * given signature
	 * 
	 * @param convention the convention, which must represent {@code __stdcall}
	 * @param sig the signature
	 * @return the depth
	 */
	protected int computeStdcallExtrapop(PrototypeModel convention, FunctionSignature sig) {
		ParameterDefinition[] arguments = sig.getArguments();
		DataType[] types = new DataType[arguments.length + 1];
		types[0] = sig.getReturnType();
		for (int i = 0; i < arguments.length; i++) {
			types[i + 1] = arguments[0].getDataType();
		}
		VariableStorage[] vsLocs = convention.getStorageLocations(program, types, false);
		Address min = null;
		Address max = null; // Exclusive
		for (VariableStorage vs : vsLocs) {
			if (vs == null) {
				continue;
			}
			for (Varnode vn : vs.getVarnodes()) {
				if (!vn.getAddress().isStackAddress()) {
					continue;
				}
				Address vnMin = vn.getAddress();
				Address vnMax = vnMin.add(vn.getSize());
				min = min == null || vnMin.compareTo(min) < 0 ? vnMin : min;
				max = max == null || vnMax.compareTo(max) > 0 ? vnMax : max;
			}
		}
		int purge = max == null ? 0 : (int) max.subtract(min);
		// AFAIK, this stdcall only applies to x86, so presume return address on stack
		return purge + program.getLanguage().getProgramCounter().getNumBytes();
	}

	/**
	 * Compute the stack change for an indirect call
	 * 
	 * @param op the low p-code op
	 * @return the depth change
	 */
	protected int computeStackChangeIndirect(PcodeOp op) {
		FunctionSignature sig = getSignatureOfIndirectCall(op);
		if (sig == null) {
			int extrapop = program.getCompilerSpec().getDefaultCallingConvention().getExtrapop();
			if (extrapop != PrototypeModel.UNKNOWN_EXTRAPOP) {
				return extrapop;
			}
			throw new PcodeExecutionException("Cannot get stack change for indirect call: " + op);
		}
		PrototypeModel convention =
			program.getCompilerSpec().matchConvention(sig.getCallingConventionName());
		if (convention == null) {
			warnings.add(new UnspecifiedConventionStackUnwindWarning(null));
			convention = program.getCompilerSpec().getDefaultCallingConvention();
		}
		int extrapop = convention.getExtrapop();
		if (extrapop != PrototypeModel.UNKNOWN_EXTRAPOP) {
			return extrapop;
		}
		return computeStdcallExtrapop(convention, sig);
	}

	/**
	 * Apply the given stack change to the machine state
	 * 
	 * <p>
	 * The overall effect is simply: {@code SP = SP + change}
	 * 
	 * @param change the change
	 */
	protected void adjustStack(int change) {
		Sym spVal = state.getVar(sp, reason);
		int size = sp.getNumBytes();
		Sym spChanged = arithmetic.binaryOp(PcodeOp.INT_ADD, size, size, spVal, size,
			arithmetic.fromConst(change, size));
		state.setVar(sp, spChanged);
	}

	@Override
	public void executeIndirectCall(PcodeOp op, PcodeFrame frame) {
		int change = computeStackChangeIndirect(op);
		assert change != PrototypeModel.UNKNOWN_EXTRAPOP;
		adjustStack(change);
	}

	@Override
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		// This should always end a basic block, so just do nothing
	}

	@Override
	protected void doExecuteIndirectBranch(PcodeOp op, PcodeFrame frame) {
		// This should always end a basic block, so just do nothing
	}
}
