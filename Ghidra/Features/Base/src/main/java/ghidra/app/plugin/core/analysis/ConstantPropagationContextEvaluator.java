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
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.function.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.VarnodeContext;
import ghidra.util.task.TaskMonitor;

/**
 * The ConstantPropogatorEvaluator is used as the evaluator for the SymbolicPropagator when finding constant
 * references and laying them down for a generic processor.  Extend this class to add additional checks
 * and behaviors necessary for a unique processor such as the PowerPC.
 * 
 * This implementation checks values that are problematic and will not make references to those locations.
 *     0-256, 0xffffffff, 0xffff, 0xfffffffe
 * For some embedded processors these locations or these locations in certain address spaces are OK,
 * so the evaluateConstant and evaluateReference should be overridden.
 * 
 * The base implementation supports setting of an option to trust values read from writable memory.
 * 
 * An addressset of locations that were computed jump flows where the flow is unknown is
 * available in a destination address set.
 */

public class ConstantPropagationContextEvaluator extends ContextEvaluatorAdapter {
	private static final int MAX_UNICODE_STRING_LEN = 200;
	private static final int MAX_CHAR_STRING__LEN = 100;
	protected AddressSet destSet = new AddressSet();
	private boolean trustMemoryWrite = false;
	private boolean createDataFromPointers = false;
	private long minStoreLoadOffset = 4;
	private long minSpeculativeOffset = 1024;   // from the beginning of memory
	private long maxSpeculativeOffset = 256;    // from the end of memory
	
	protected TaskMonitor monitor;
	private final int NULL_TERMINATOR_PROBE = -1;

	public ConstantPropagationContextEvaluator(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	/**
	 * @param monitor TODO
	 * @param trustMemoryWrite - true to trust values read from memory that is marked writable
	 */
	public ConstantPropagationContextEvaluator(TaskMonitor monitor, boolean trustMemoryWrite) {
		this.monitor = monitor;
		this.trustMemoryWrite = trustMemoryWrite;
	}

	public ConstantPropagationContextEvaluator(TaskMonitor monitor,
			boolean trustWriteMemOption, long minStoreLoadRefAddress,
			long minSpeculativeRefAddress, long maxSpeculativeRefAddress) {
		this(monitor, trustWriteMemOption);
		this.minStoreLoadOffset = minStoreLoadRefAddress;
		this.minSpeculativeOffset = minSpeculativeRefAddress;
		this.maxSpeculativeOffset = maxSpeculativeRefAddress;
	}
	
	/**
	 * Set option to trust reads from memory that is marked writeable
	 * 
	 * @param trustWriteableMemOption true to trust values read from memory that is marked writable
	 * @return this
	 */
	public ConstantPropagationContextEvaluator setTrustWritableMemory(boolean trustWriteableMemOption) {
		trustMemoryWrite = trustWriteableMemOption;
		return this;
	}

	/**
	 * Set mimimum speculative memory offset for references
	 * 
	 * @param minSpeculativeRefAddress minimum address offset
	 * @return this
	 */
	public ConstantPropagationContextEvaluator setMinpeculativeOffset(long minSpeculativeRefAddress) {
		minSpeculativeOffset = minSpeculativeRefAddress;
		return this;
	}
	
	/**
	 * Set maximum speculative memory offset for references
	 * 
	 * @param maxSpeculativeRefAddress maximum address offset
	 * @return this
	 */
	public ConstantPropagationContextEvaluator setMaxSpeculativeOffset(long maxSpeculativeRefAddress) {
		maxSpeculativeOffset = maxSpeculativeRefAddress;
		return this;
	}
	
	/**
	 * Set maximum speculative memory offset for references
	 * 
	 * @param minStoreLoadRefAddress maximum address offset
	 * @return this
	 */
	public ConstantPropagationContextEvaluator setMinStoreLoadOffset(long minStoreLoadRefAddress) {
		maxSpeculativeOffset = minStoreLoadRefAddress;
		return this;
	}
	
	/**
	 * Set option to create complex data for pointers if the datatype is known
	 * 
	 * @param doCreateData true to create complex data types if the data type is known
	 * @return this
	 */
	public ConstantPropagationContextEvaluator setCreateComplexDataFromPointers(boolean doCreateData) {
		createDataFromPointers = doCreateData;
		return this;
	}
	
	/**
	 * The computed destination set is useful if follow on switch analysis is to be done.
	 * 
	 * @return a set of destinations that have computed flow where the flow is unknown
	 */
	public AddressSet getDestinationSet() {
		return destSet;
	}

	/**
	 * If you override this method, and the default behavior of checking 0-256 and mask values is desired,
	 * call super.evaluateConstant() in your overriden method.
	 */
	@Override
	public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop,
			Address constant, int size, DataType dataType, RefType refType) {

		// Constant references below minSpeculative or near the end of the address space are suspect,
		// even if memory exists for those locations.
		AddressSpace space = constant.getAddressSpace();
		long maxAddrOffset = space.getMaxAddress().getOffset();
		long wordOffset = constant.getOffset();

		if (((wordOffset >= 0 && wordOffset < minSpeculativeOffset) ||
			(Math.abs(maxAddrOffset - wordOffset) < maxSpeculativeOffset)) &&
			!space.isExternalSpace()) {
			return null;
		}

		// could just be integer -1 extended into address
		if (wordOffset == 0xffffffffL || wordOffset == 0xffffL || wordOffset == -1L) {
			return null;
		}

		return constant;
	}

	/**
	 * If you override this method, and the default behavior of checking 0-256 and mask values is desired,
	 * call super.evaluateReference() in your overriden method.
	 */
	@Override
	public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
			Address address, int size, DataType dataType, RefType refType) {
		
		// special check for parameters, evaluating the call, an uncomputed call wouldn't get here normally
		// really there should be another callback when adding parameters
		if (refType.isCall() && !refType.isComputed() && pcodeop == PcodeOp.UNIMPLEMENTED) {
			return true;
		}

		// unless this is a direct address copy, don't trust computed accesses below minStoreLoadOffset
		//     External spaces can have low addresses... so don't check them
		AddressSpace space = address.getAddressSpace();
		if (space.isExternalSpace()) {
			return true;
		}

		long maxAddrOffset = space.getMaxAddress().getAddressableWordOffset();
		long wordOffset = address.getAddressableWordOffset();
		boolean isKnownReference = !address.isConstantAddress();

		if (pcodeop != PcodeOp.COPY && ((wordOffset >= 0 && wordOffset < minStoreLoadOffset) ||
			(Math.abs(maxAddrOffset - wordOffset) < minStoreLoadOffset))) {
			if (!isKnownReference) {
				return false;
			}
			PcodeOp[] pcode = instr.getPcode();
			if (pcode.length > 1) { // for simple pcode, assume it is a good location.
				return false;
			}
		}

		Program program = instr.getProgram();
		AutoAnalysisManager aMgr= AutoAnalysisManager.getAnalysisManager(program);
		
		// if data reference, handle data
		if (refType.isData()) {
			createPointedToData(aMgr, program, address, refType, dataType, size);
		}

		// if flowing to an address, disassemble it
		// only disassemble in executable memory
		Memory memory = program.getMemory();
		if (refType.isFlow() && !refType.isIndirect() &&
			!memory.isExternalBlockAddress(address) && memory.getExecuteSet().contains(address)) {
			Data udata = program.getListing().getUndefinedDataAt(address);
			if (udata != null) {
				DisassembleCommand cmd = new DisassembleCommand(address, null, true);
				cmd.applyTo(program, monitor);
			}
			// 
			// TODO: need to kick analysis if the target is a function and non-returning
			// Function functionAt = program.getFunctionManager().getFunctionAt(address);
			// if (functionAt != null && functionAt.hasNoReturn()) {
			//	aMgr.functionModifierChanged(address);
			// }
		}

		return true;
	}
	
	private int createPointedToData(AutoAnalysisManager aMgr, Program program, Address address, RefType refType, DataType dataType, int size) {
		// don't do in external memory
		if (program.getMemory().isExternalBlockAddress(address) || address.isExternalAddress()) {
			return 0;
		}
		
		// don't create if not in real memory
		if (!program.getMemory().contains(address)) {
			return 0;
		}
		
		// Get the data type that is pointed to, strip off pointer, or pointer typedef
		DataType pointedToDT = null;
		if (dataType instanceof Pointer ptr) {
			pointedToDT = ptr.getDataType();
		}
		else if ((dataType instanceof TypeDef typeDef && typeDef.getBaseDataType() instanceof Pointer ptr)) {
			pointedToDT = ptr.getDataType();
		}
		
		// if this is a function pointer, create the code/function/signature
		if (pointedToDT instanceof FunctionDefinition funcDefn) {
			createFunctionApplySignature(aMgr, program, address, funcDefn);
			return dataType.getLength();
		}
		
		// otherwise it is data
		
		if (dataType != null) {
			// System.out.println("@ " + address + " Data Type - " + dataType);
		}
		
		return createData(program, address, pointedToDT, size);
	}

	/**
	 * Create Data at an address in the program
	 * 
	 * @param program the program
	 * @param address location to create data
	 * @param dataType dataType if known
	 * @param size size of the data type (from a read/write)
	 * @return size of the data item created, or 0 if none created
	 */
	private int createData(Program program, Address address, DataType dataType, int size) {
		// defined data (that isn't an undefined) don't do anything
		Data data = program.getListing().getDataAt(address);
		if (data == null || !Undefined.isUndefined(data.getDataType())) {
			return 0;
		}
		
		// get a default undefined data type of the right size for the access
		DataType dt = Undefined.getUndefinedDataType(size);
		
		int maxLen = -1;
		if (createDataFromPointers && dataType != null) {
			DataType originalDT = dataType;

			// if typedef, get the base type
			if (dataType instanceof TypeDef typeDef) {
				dataType = typeDef.getBaseDataType();
			}
			
			if (dataType instanceof CharDataType) {
				// Use Terminated in case strings are referenced offcut
				maxLen = getRestrictedStringLen(program, address, TerminatedStringDataType.dataType, MAX_CHAR_STRING__LEN);
				if (maxLen > 0) {
					dt = TerminatedStringDataType.dataType;
				}
			} else if (dataType instanceof WideCharDataType) {
				maxLen = getRestrictedStringLen(program, address, TerminatedUnicodeDataType.dataType, MAX_UNICODE_STRING_LEN);
				if (maxLen > 0) {
					dt = TerminatedUnicodeDataType.dataType;
				}
			} else if (dataType instanceof Composite comp) {
				// create empty structures, they can get filled out later
				// if they don't fit later because they grow, then there will be an error at the location
				dt = originalDT; // original might have been a typedef, use original
			} else if (dataType instanceof VoidDataType) {
				// ptr to void should be ignored
				return 0;
			} else if (dataType instanceof AbstractFloatDataType) {
				dt = dataType;
			} else {
				// don't do any other types other than above for now
				return 0;
			}
		} else if (size < 1 || size > 8) {
			return 0;
		}
		
		try {
			// create data at the location so that we record the access size
			//   the data is undefined, and SHOULD be overwritten if something
			//   else knows better about the location.
			if (maxLen > 0) {
				data = DataUtilities.createData(program, address, dt, maxLen,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			} else {
				data = DataUtilities.createData(program, address, dt, -1,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return data.getLength();
		}
		catch (CodeUnitInsertionException e) {
			// couldn't create data
		}

		return 0;
	}

	/**
	 * Create a function/code at a location and apply the 
	 * 
	 * @param aMgr auto analysis manager
	 * @param program the program
	 * @param address location to create function
	 * @param funcDefn function definition if known
	 */
	private void createFunctionApplySignature(AutoAnalysisManager aMgr, Program program,
			Address address, FunctionDefinition funcDefn) {

		// System.out.println("@ " + address + " - Typedef Function " + ((FunctionDefinition)ptrToDT).getPrototypeString());

		Listing listing = program.getListing();
		
		// defined data (that isn't an undefined) don't do anything
		Data data = listing.getDefinedDataContaining(address);
		if (data != null) {
			return;
		}
		
		// if memory is undefined bytes, don't disassemble or create function
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || !block.isInitialized()) {
			return;
		}

		// normalize the address to where code should start (ARM and MIPS can be offset by one)
		Address normalizedAddr = PseudoDisassembler.getNormalizedDisassemblyAddress(program, address);
		if (!listing.isUndefined(normalizedAddr, normalizedAddr)) {
			// if not undefined, must be an instruction to continue
			Instruction instr = listing.getInstructionAt(normalizedAddr);
			if (instr == null) {
				return;
			}
		} else {
			// if nothing defined here, disassemble
			address = PseudoDisassembler.setTargeContextForDisassembly(program, address);
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			cmd.applyTo(program, monitor);
		}
		
		// see if there is an existing function
		FunctionManager funcMgr = program.getFunctionManager();
		Function func = funcMgr.getFunctionAt(address);
		// if no function at the address, make sure not in the middle of a function
		if (func == null) {
			func = funcMgr.getFunctionContaining(address);
			// don't create a function in the middle of another
			if (func != null) {
				return;
			}
		}
		
		if (func != null) {
			if (func.isThunk()) {
				return;
			}

			SourceType mostTrusted = getMostTrustedParameterSource(func);
			if (SourceType.ANALYSIS.isLowerPriorityThan(mostTrusted)) {
				return;
			}
		} else {
			CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(address, false);
			aMgr.schedule(createFunctionCmd, AnalysisPriority.FUNCTION_ANALYSIS.priority());
		}
		
		// only apply the signature if actually creating data, the function/code has already been created
		if (!createDataFromPointers) {
			return;
		}
		
		// if no arguments, could be an opaque function pointer, don't apply arguments
		ParameterDefinition[] arguments = funcDefn.getArguments();
		DataType returnType = funcDefn.getReturnType();
		if (arguments == null || (arguments.length == 0 && (returnType==null || Undefined.isUndefined(returnType)))) {
			return;
		}

		// applying function signatures considered data
		// don't change name, even default name
		ApplyFunctionSignatureCmd applyFunctionSignatureCmd = new ApplyFunctionSignatureCmd(address, funcDefn, SourceType.ANALYSIS, true, FunctionRenameOption.NO_CHANGE);
		aMgr.schedule(applyFunctionSignatureCmd, AnalysisPriority.FUNCTION_ANALYSIS.after().priority());
	}
	
	private SourceType getMostTrustedParameterSource(Function func) {
		SourceType highestSource = func.getSignatureSource();
		Parameter[] parameters = func.getParameters();
		for (Parameter parameter : parameters) {
			SourceType paramSource = parameter.getSource();
			if (paramSource.isHigherPriorityThan(highestSource)) {
				highestSource = paramSource;
			}
		}
		return highestSource;
	}

	/**
	 * Add instructions to destination set for unknown computed branches.
	 */
	@Override
	public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
		FlowType flowType = instruction.getFlowType();
		if (!flowType.isJump()) {
			return false;
		}

		/**
		 * For jump targets, that have no computed reference, add the jump location to a set
		 * to evaluate as a potential switch statement.
		 */
		Reference[] refs = instruction.getReferencesFrom();
		if (refs.length <= 0 || (refs.length == 1 && refs[0].getReferenceType().isData())) {
			destSet.addRange(instruction.getMinAddress(), instruction.getMinAddress());
		}
		return false;
	}

	/**
	 * Trust access to writable memory based on initialized option.
	 */
	@Override
	public boolean allowAccess(VarnodeContext context, Address addr) {
		return trustMemoryWrite;
	}
	
	/**
	 * Looks at bytes at given address and converts to format String
	 * 
	 * @param address Address of format String
	 * @param pointer Pointer "type" of string
	 * @return format String
	 */
	int getRestrictedStringLen(Program program, Address address, AbstractStringDataType dataType, int maxLength) {
		
		maxLength = getMaxStringLength(program, address, maxLength);

		MemoryBufferImpl memoryBuffer =
			new MemoryBufferImpl(program.getMemory(), address);
		
		StringDataInstance stringDataInstance = dataType.getStringDataInstance(memoryBuffer, dataType.getDefaultSettings(), -1);
		stringDataInstance.getStringDataTypeGuess();
		
		int detectedLength = stringDataInstance.getStringLength();
		if (detectedLength == -1) {
			return 0;
		}
		
		if (detectedLength > maxLength) {
			detectedLength = maxLength;
		}
		
		return detectedLength;
	}
	
	/**
	 * Get the number of bytes to the next reference, or the max length
	 * 
	 * @param program
	 * @param address
	 * @return maximum length to create the string
	 */
	private int getMaxStringLength(Program program, Address address, int maxLen) {
		AddressIterator refIter = program.getReferenceManager().getReferenceDestinationIterator(address.next(), true);
		Address next = refIter.next();
		if (next == null) {
			return -1;
		}
		
		long len = -1;
		try {
			len = next.subtract(address);
			if (len > maxLen) {
				len = maxLen;
			}
			return (int) len;
		} catch (IllegalArgumentException exc) {
			// bad address subtraction
		}
		return (int) len;
	}
}
