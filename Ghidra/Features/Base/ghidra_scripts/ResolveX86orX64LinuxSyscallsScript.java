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
//Uses overriding references and the symbolic propogator to resolve system calls
//@category Analysis
import java.io.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import generic.jar.ResourceFile;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This script will resolve system calls for x86 or x64 Linux binaries.
 * It assumes that in the x64 case, the syscall native instruction is used to make system calls,
 * and in the x86 case, system calls are made via an indirect call to GS:[0x10].
 * It should be straightforward to modify this script for other cases.
 */
public class ResolveX86orX64LinuxSyscallsScript extends GhidraScript {

	//disassembles to "CALL dword ptr GS:[0x10]"
	private static final byte[] x86_bytes = { 0x65, -1, 0x15, 0x10, 0x00, 0x00, 0x00 };

	private static final String X86 = "x86";

	private static final String SYSCALL_SPACE_NAME = "syscall";

	private static final int SYSCALL_SPACE_LENGTH = 0x10000;

	//this is the name of the userop (aka CALLOTHER) in the pcode translation of the
	//native "syscall" instruction
	private static final String SYSCALL_X64_CALLOTHER = "syscall";

	//a set of names of all syscalls that do not return
	private static final Set<String> noreturnSyscalls = Set.of("exit", "exit_group");

	//tests whether an instruction is making a system call
	private Predicate<Instruction> tester;

	//register holding the syscall number
	private String syscallRegister;

	//datatype archive containing signature of system calls
	private String datatypeArchiveName;

	//file containing map from syscall numbers to syscall names
	//note that different architectures can have different system call numbers, even
	//if they're both Linux...
	private String syscallFileName;

	//the type of overriding reference to apply 
	private RefType overrideType;

	//the calling convention to use for system calls (must be defined in the appropriate .cspec file)
	private String callingConvention;

	@Override
	protected void run() throws Exception {

		if (!(currentProgram.getExecutableFormat().equals(ElfLoader.ELF_NAME) &&
			currentProgram.getLanguage().getProcessor().toString().equals(X86))) {
			popup("This script is intended for x86 or x64 Linux files");
			return;
		}

		//determine whether the executable is 32 or 64 bit and set fields appropriately
		int size = currentProgram.getLanguage().getLanguageDescription().getSize();
		if (size == 64) {
			tester = ResolveX86orX64LinuxSyscallsScript::checkX64Instruction;
			syscallRegister = "RAX";
			datatypeArchiveName = "generic_clib_64";
			syscallFileName = "x64_linux_syscall_numbers";
			overrideType = RefType.CALLOTHER_OVERRIDE_CALL;
			callingConvention = "syscall";
		}
		else {
			tester = ResolveX86orX64LinuxSyscallsScript::checkX86Instruction;
			syscallRegister = "EAX";
			datatypeArchiveName = "generic_clib";
			syscallFileName = "x86_linux_syscall_numbers";
			overrideType = RefType.CALL_OVERRIDE_UNCONDITIONAL;
			callingConvention = "syscall";
		}

		//get the space where the system calls live.  
		//If it doesn't exist, create it.
		AddressSpace syscallSpace =
			currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		if (syscallSpace == null) {
			//don't muck with address spaces if you don't have exclusive access to the program.
			if (!currentProgram.hasExclusiveAccess()) {
				popup("Must have exclusive access to " + currentProgram.getName() +
					" to run this script");
				return;
			}
			Address startAddr = currentProgram.getAddressFactory().getAddressSpace(
				BasicCompilerSpec.OTHER_SPACE_NAME).getAddress(0x0L);
			AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
				SYSCALL_SPACE_NAME, null, this.getClass().getName(), startAddr,
				SYSCALL_SPACE_LENGTH, true, true, true, false, true);
			if (!cmd.applyTo(currentProgram)) {
				popup("Failed to create " + SYSCALL_SPACE_NAME);
				return;
			}
			syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		}
		else {
			printf("AddressSpace %s found, continuing...\n", SYSCALL_SPACE_NAME);
		}

		//get all of the functions that contain system calls
		//note that this will not find system call instructions that are not in defined functions
		Map<Function, Set<Address>> funcsToCalls = getSyscallsInFunctions(currentProgram, monitor);

		if (funcsToCalls.isEmpty()) {
			popup("No system calls found (within defined functions)");
			return;
		}

		//get the system call number at each callsite of a system call.
		//note that this is not guaranteed to succeed at a given system call call site -
		//it might be hard (or impossible) to determine a specific constant
		Map<Address, Long> addressesToSyscalls =
			resolveConstants(funcsToCalls, currentProgram, monitor);

		if (addressesToSyscalls.isEmpty()) {
			popup("Couldn't resolve any syscall constants");
			return;
		}

		//get the map from system call numbers to system call names
		//you might have to create this yourself!
		Map<Long, String> syscallNumbersToNames = getSyscallNumberMap();

		//at each system call call site where a constant could be determined, create
		//the system call (if not already created), then add the appropriate overriding reference
		//use syscallNumbersToNames to name the created functions
		//if there's not a name corresponding to the constant use a default 
		for (Entry<Address, Long> entry : addressesToSyscalls.entrySet()) {
			Address callSite = entry.getKey();
			Long offset = entry.getValue();
			Address callTarget = syscallSpace.getAddress(offset);
			Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);
			if (callee == null) {
				String funcName = "syscall_" + String.format("%08X", offset);
				if (syscallNumbersToNames.get(offset) != null) {
					funcName = syscallNumbersToNames.get(offset);
				}
				callee = createFunction(callTarget, funcName);
				callee.setCallingConvention(callingConvention);

				//check if the function name is one of the non-returning syscalls
				if (noreturnSyscalls.contains(funcName)) {
					callee.setNoReturn(true);
				}
			}
			Reference ref = currentProgram.getReferenceManager().addMemoryReference(callSite,
				callTarget, overrideType, SourceType.USER_DEFINED, Reference.MNEMONIC);
			//overriding references must be primary to be active
			currentProgram.getReferenceManager().setPrimary(ref, true);
		}

		//finally, open the appropriate data type archive and apply its function data types
		//to the new system call space, so that the system calls have the correct signatures
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		DataTypeManagerService service = mgr.getDataTypeManagerService();
		List<DataTypeManager> dataTypeManagers = new ArrayList<>();
		dataTypeManagers.add(service.openDataTypeArchive(datatypeArchiveName));
		dataTypeManagers.add(currentProgram.getDataTypeManager());
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(dataTypeManagers,
			new AddressSet(syscallSpace.getMinAddress(), syscallSpace.getMaxAddress()),
			SourceType.USER_DEFINED, false, false);
		cmd.applyTo(currentProgram);
	}

	//TODO: better error checking!
	private Map<Long, String> getSyscallNumberMap() {
		Map<Long, String> syscallMap = new HashMap<>();
		ResourceFile rFile = Application.findDataFileInAnyModule(syscallFileName);
		if (rFile == null) {
			popup("Error opening syscall number file, using default names");
			return syscallMap;
		}
		try (FileReader fReader = new FileReader(rFile.getFile(false));
				BufferedReader bReader = new BufferedReader(fReader)) {
			String line = null;
			while ((line = bReader.readLine()) != null) {
				//lines starting with # are comments
				if (!line.startsWith("#")) {
					String[] parts = line.trim().split(" ");
					Long number = Long.parseLong(parts[0]);
					syscallMap.put(number, parts[1]);
				}
			}
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error reading syscall map file", e.getMessage(), e);
		}
		return syscallMap;
	}

	/**
	 * Scans through all of the functions defined in {@code program} and returns
	 * a map which takes a function to the set of address in its body which contain
	 * system calls
	 * @param program program containing functions
	 * @param tMonitor monitor
	 * @return map function -> addresses in function containing syscalls
	 * @throws CancelledException if the user cancels
	 */
	private Map<Function, Set<Address>> getSyscallsInFunctions(Program program,
			TaskMonitor tMonitor) throws CancelledException {
		Map<Function, Set<Address>> funcsToCalls = new HashMap<>();
		for (Function func : program.getFunctionManager().getFunctionsNoStubs(true)) {
			tMonitor.checkCanceled();
			for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
				if (tester.test(inst)) {
					Set<Address> callSites = funcsToCalls.get(func);
					if (callSites == null) {
						callSites = new HashSet<>();
						funcsToCalls.put(func, callSites);
					}
					callSites.add(inst.getAddress());
				}
			}
		}
		return funcsToCalls;
	}

	/**
	 * Uses the symbolic propogator to attempt to determine the constant value in
	 * the syscall register at each system call instruction
	 * 
	 * @param funcsToCalls map from functions containing syscalls to address in each function of 
	 * the system call
	 * @param program containing the functions
	 * @return map from addresses of system calls to system call numbers
	 * @throws CancelledException if the user cancels
	 */
	private Map<Address, Long> resolveConstants(Map<Function, Set<Address>> funcsToCalls,
			Program program, TaskMonitor tMonitor) throws CancelledException {
		Map<Address, Long> addressesToSyscalls = new HashMap<>();
		Register syscallReg = program.getLanguage().getRegister(syscallRegister);
		for (Function func : funcsToCalls.keySet()) {
			Address start = func.getEntryPoint();
			ContextEvaluator eval = new ConstantPropagationContextEvaluator(true);
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.flowConstants(start, func.getBody(), eval, true, tMonitor);
			for (Address callSite : funcsToCalls.get(func)) {
				Value val = symEval.getRegisterValue(callSite, syscallReg);
				if (val == null) {
					createBookmark(callSite, "System Call",
						"Couldn't resolve value of " + syscallReg);
					printf("Couldn't resolve value of " + syscallReg + " at " + callSite + "\n");
					continue;
				}
				addressesToSyscalls.put(callSite, val.getValue());
			}
		}
		return addressesToSyscalls;
	}

	/**
	 * Checks whether an x86 native instruction is a system call
	 * @param inst instruction to check
	 * @return true precisely when the instruction is a system call
	 */
	private static boolean checkX86Instruction(Instruction inst) {
		try {
			return Arrays.equals(x86_bytes, inst.getBytes());
		}
		catch (MemoryAccessException e) {
			Msg.info(ResolveX86orX64LinuxSyscallsScript.class,
				"MemoryAccessException at " + inst.getAddress().toString());
			return false;
		}
	}

	/**
	 * Checks whether an x64 instruction is a system call
	 * @param inst instruction to check
	 * @return true precisely when the instruction is a system call
	 */
	private static boolean checkX64Instruction(Instruction inst) {
		boolean retVal = false;
		for (PcodeOp op : inst.getPcode()) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				int index = (int) op.getInput(0).getOffset();
				if (inst.getProgram().getLanguage().getUserDefinedOpName(index).equals(
					SYSCALL_X64_CALLOTHER)) {
					retVal = true;
				}
			}
		}
		return retVal;
	}

}
