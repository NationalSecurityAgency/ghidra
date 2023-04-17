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

package ghidra.app.util.bin.format.dwarf4.next;

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.DW_AT_low_pc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.plugin.core.analysis.DwarfLineNumberAnalyzer;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.line.StateMachine;
import ghidra.app.util.bin.format.dwarf.line.StatementProgramInstructions;
import ghidra.app.util.bin.format.dwarf.line.StatementProgramPrologue;
import ghidra.app.util.bin.format.dwarf4.DIEAggregate;
import ghidra.app.util.bin.format.dwarf4.DWARFLocation;
import ghidra.app.util.bin.format.dwarf4.DebugInfoEntry;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunctionImporter.DWARFFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DWARFLocalImporter extends DWARFVariableVisitor {

	private final TaskMonitor monitor;
	private final Map<Function, Address> prologue_ends;

	public DWARFLocalImporter(DWARFProgram prog, DWARFDataTypeManager dwarfDTM,TaskMonitor monitor) {
		super( prog, prog.getGhidraProgram(), dwarfDTM);
		this.monitor = monitor;
		this.prologue_ends = new HashMap<>();
	}

	private void commitLocal(Function func, DWARFVariable dvar) throws InvalidInputException {
		// Attempt to add the variable
		Variable var = buildVariable(dvar);

		// check for an existing local variable with conflict storage.
		boolean hasConflict = false;

		Msg.info(this, "Adding " + dvar.dni.getName());
		for (Variable existingVar : func.getAllVariables()) {
			if (existingVar.getFirstUseOffset() == var.getFirstUseOffset()
					&& existingVar.getVariableStorage().intersects(var.getVariableStorage())) {
				if ((existingVar instanceof LocalVariable) && Undefined.isUndefined(existingVar.getDataType())) {
					// ignore locals with undefined type - they will be removed below
					continue;
				}
				hasConflict = true;
				break;
			}
		}
		if (hasConflict) {
			appendComment(func.getEntryPoint().add(dvar.lexicalOffset), CodeUnit.EOL_COMMENT,
					"Scope for omitted local variable " + var.toString() + " starts here", "; ");
			return;
		}

		try {
			VariableUtilities.checkVariableConflict(func, null, var.getVariableStorage(), true);
			func.addLocalVariable(var, SourceType.IMPORTED);
		} catch (DuplicateNameException e) {
			int count = 1;
			// Add the variable with an unused name
			String baseName = var.getName();
			while (!monitor.isCancelled()) {
				try {
					var.setName(baseName + "_" + Integer.toString(count), SourceType.IMPORTED);
					func.addLocalVariable(var, SourceType.IMPORTED);
				} catch (DuplicateNameException e1) {
					count++;
					continue;
				}
				break;
			}
		}

	}
	
	
	static class LineExecutorFactory implements DwarfLineNumberAnalyzer.StatementProgramInstructionsFactory {
		private final DWARFProgram prog;
		private final Map<Function, Address> addresses;
		
		
		public LineExecutorFactory(DWARFProgram prog, Map<Function, Address> addresses) {
			super();
			this.prog = prog;
			this.addresses = addresses;
		}


		@Override
		public StatementProgramInstructions create(BinaryReader reader, StateMachine machine,
				StatementProgramPrologue prologue) {
			return new LineExecutor(reader, machine, prologue, this.prog, this.addresses);
		}
		
	}
	
	static class LineExecutor extends StatementProgramInstructions {

		private final DWARFProgram prog;
		private final Map<Function, Address> addresses;
		
		
		
		public LineExecutor(BinaryReader reader, StateMachine machine, StatementProgramPrologue prologue,
				DWARFProgram prog,Map<Function, Address> addresses) {
			super(reader, machine, prologue);
			this.prog = prog;
			this.addresses = addresses;
		}

	

		@Override
		protected void emitRow(StateMachine state, StatementProgramPrologue prologue) {
			if (state.isPrologueEnd) {
				var addr = prog.getGhidraProgram().getAddressFactory().getDefaultAddressSpace().getAddress(((long) state.address) + prog.getProgramBaseAddressFixup());
				Msg.info(this, "Prologue_end: " + addr.toString());
				var func = prog.getGhidraProgram().getFunctionManager().getFunctionContaining(addr);
				if (func != null) {
					this.addresses.put(func,addr);
				}
			}
		}
		
	}
	
	
	private void collectPrologueEnds() {
		DwarfLineNumberAnalyzer.visitLines(currentProgram, monitor, new LineExecutorFactory(this.prog, this.prologue_ends));
	}
	
	public void process()
			throws CancelledException {
		this.collectPrologueEnds();
		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(prog, "DWARF - Create Funcs & Symbols", monitor)) {
			monitor.checkCanceled();
			try {
				if (diea.getTag() == DWARFTag.DW_TAG_subprogram) {

					try {
						processSubprogram(diea);
					} catch (InvalidInputException e) {
						Msg.error(this, "Failed to process subprog " + diea.getHexOffset(), e);
					}
				}
			} catch (OutOfMemoryError oom) {
				throw oom;
			} catch (Throwable th) {
				Msg.error(this, "Error when processing DWARF information for DIE " + diea.getHexOffset(), th);
				Msg.info(this, "DIE info:\n" + diea.toString());
			}
		}

	}

	private void processFuncChildren(DebugInfoEntry die, DWARFFunction dfunc, ArrayList<DWARFVariable> vbuf, Optional<Address> scope_start) throws IOException, InvalidInputException {
		var diea = prog.getAggregate(die);
		switch(diea.getTag()) {
		case DWARFTag.DW_TAG_lexical_block:
			if (diea.hasAttribute(DW_AT_low_pc)) {
				var lpc = diea.getLowPC(-1);
				if (lpc != -1) {
					scope_start = Optional.of(toAddr(lpc));
				}
			}
			for (var child : diea.getHeadFragment().getChildren()) {
				Msg.info(this, "Starting block: " + scope_start.toString());
				processFuncChildren(child, dfunc, vbuf, scope_start);
			}
			break;
		case DWARFTag.DW_TAG_variable:
			var v = this.processVariable(diea, dfunc, scope_start.orElseGet(()-> null), dfunc.address.getOffset());
			if (v != null) {
				vbuf.add(v);
			}
			break;
		}
	}
	
	private void processSubprogram(DIEAggregate diea) throws InvalidInputException, IOException {
		var dfunc = this.populateDWARFFunc(diea);
		var gfunc = currentProgram.getFunctionManager().getFunctionAt(dfunc.address);
		if (gfunc == null) {
			return;
		}
		
		Msg.info(this, "Working on func " + gfunc.getName());
		
		var vlist = new ArrayList<DWARFVariable>();
		
		for (var child : diea.getHeadFragment().getChildren()) {
			processFuncChildren(child, dfunc, vlist, Optional.empty());
		}
		
		if (!dfunc.localVarErrors) {
			for (var v: vlist) {
				if(v.isStackOffset) {
					commitLocal(gfunc, v);
				}
			}
		}
		
	}
	
	private Optional<Address> getPrologueAddr(Function gfunc) {
		return Optional.ofNullable(this.prologue_ends.get(gfunc));
	}

	@Override
	protected Optional<Long> resolveStackOffset(long off, DWARFLocation loc, DWARFFunction dfunc, boolean validRange, Optional<Address> block_start) {
		var func = this.currentProgram.getFunctionManager().getFunctionAt(dfunc.address);
		var live_at = block_start;
		if (validRange) {
			live_at = Optional.of(toAddr(loc.getRange().getFrom()));
		}
		
		if (!live_at.isPresent()) {
			live_at = getPrologueAddr(func);
		}
		
		if (live_at.isPresent() && func != null && prog.getRegisterMappings().getGhidraReg( prog.getRegisterMappings().getDWARFStackPointerRegNum()) == currentProgram.getCompilerSpec().getStackPointer()) {
			var cdi = new CallDepthChangeInfo(func);
			var curr_sp_depth = cdi.getSPDepth(live_at.get());
			if (curr_sp_depth != Function.INVALID_STACK_DEPTH_CHANGE) {
				return Optional.of(off + curr_sp_depth);
			} else {
				Msg.warn(this, "No SP depth at addr: " + live_at);
			}
		}		
		return Optional.empty();
	}
}
