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

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class eBPFSyscallAnalyzer extends AbstractAnalyzer {
	
	private final static String PROCESSOR_NAME = "eBPF";
	private final static String SYSCALL_ADDRSPACE_NAME = "syscall";

	private final static String NAME = "eBPF Syscall Functions";
	private final static String DESCRIPTION = "Apply eBPF syscall Functions";
	
	public eBPFSyscallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before());
		setDefaultEnablement(true);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		return PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString());
	}

	/**
	 * Following the creation of a function this analyzer applies a function signature to default
	 * function if contains within the syscall space.
	 * @throws CancelledException if analysis is cancelled
	 */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) 
			throws CancelledException {
		
		AddressSpace syscallSpace = program.getAddressFactory().getAddressSpace(SYSCALL_ADDRSPACE_NAME);
		
		AddressSetView syscallSet = set.intersectRange(syscallSpace.getMinAddress(), syscallSpace.getMaxAddress());
		if (syscallSet.isEmpty()) {
			return true;
		}
		
		// Clear disassembly errors within syscall space
        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        bookmarkMgr.removeBookmarks(syscallSet, BookmarkType.ERROR, monitor);
        
        eBPFHelperDataTypes helperDataTypes = eBPFHelperDataTypes.get(program, log);
		if (helperDataTypes == null) {
			return false;
		}
		
		for (Function f : program.getFunctionManager().getFunctions(syscallSet, true)) {
			monitor.checkCancelled();
			if (f.getSymbol().getSource() != SourceType.DEFAULT) {
				continue;
			}
			applySyscallSignature(f, helperDataTypes);
		}
		return true;
	}
	
	private void applySyscallSignature(Function func, eBPFHelperDataTypes helperDataTypes) {
		
		Program program = func.getProgram();
		
		int helperId = (int) func.getEntryPoint().getOffset();
		
		FunctionDefinition helperDef = helperDataTypes.getHelperFunctionDef(helperId);
		
		if (helperDef == null) {
			try {
				func.setName("bpf_undef_0x" + Integer.toHexString(helperId), SourceType.ANALYSIS);
			}
			catch (DuplicateNameException | InvalidInputException e) {
				// ignore
			}
		}
		else {
		    ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(), helperDef, SourceType.ANALYSIS);
		    cmd.applyTo(program);
		}

		
	}
}
