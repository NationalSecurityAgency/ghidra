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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HCS12ConstantAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "HCS12";

	public HCS12ConstantAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		return true;
	}
	
	private long hcs12TranslatePagedAddress(long addrWordOffset) {
		
		long page = (addrWordOffset >> 16) & 0xff;
		
		long addr = addrWordOffset & 0xffff;

		// Register address
		if ( (addr  & 0xfC00) == 0x0) {
			return addr;
		}
		
		// EPage address
		if ((addr & 0xfc00) ==0x800) {
			return 0x100000 | ((page << 10)  | (addr & 0x3ff));
		}
		
		// EPage FF fixed address
		if ((addr & 0xfc00) ==0xC00) {
			return (0x4FF << 10) | (addr & 0x3ff);
		}
		
		// RPage address
		if ((addr & 0xf000) ==0x1000) {
			return (page << 12) | (addr & 0xfff);
		}
		
		// RPage FE fixed address
		if ((addr & 0xf000) ==0x2000) {
			return (0xFE << 12) | (addr & 0xfff);
		}
		
		// RPage FF fixed address
		if ((addr & 0xf000) ==0x3000) {
			return (0xFF << 12) | (addr & 0xfff);
		}

		// PPage FD fixed address
		if ((addr & 0xc000) ==0x4000) {
			return 0x400000 | (0xFD << 14) | (addr & 0x3fff);
		}
		
		// PPage address
		if ((addr & 0xc000) ==0x8000) {
			return 0x400000 | (page << 14) | (addr & 0x3fff);
		}
		
		// PPage FF fixed address
		if ((addr & 0xc000) ==0xC000) {
			return 0x400000 | (0xFF << 14) | (addr & 0x3fff);
		}
		
		return addr;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet,
			final SymbolicPropogator symEval, final TaskMonitor monitor) throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, RefType refType) {

				if ((refType.isRead() || refType.isWrite()) &&
					adjustPagedAddress(instr, address, refType)) {
					return false;
				}
				return super.evaluateReference(context, instr, pcodeop, address, size, refType);
			}

			@Override
			public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop, Address constant,
					int size, RefType refType) {
				// TODO Auto-generated method stub
				return super.evaluateConstant(context, instr, pcodeop, constant, size, refType);
			}

			private boolean adjustPagedAddress(Instruction instr, Address address, RefType refType) {
				PcodeOp[] pcode = instr.getPcode();
				for (PcodeOp op : pcode) {
					int numin = op.getNumInputs();
					if (numin < 1) {
						continue;
					}
					if (op.getOpcode() != PcodeOp.CALLOTHER) {
						continue;
					}
					String opName = instr.getProgram().getLanguage().getUserDefinedOpName(
						(int) op.getInput(0).getOffset());
					if (opName != null && opName.equals("segment") && numin > 2) {
						// assume this is a poorly created segment op addr
						long high = address.getOffset() >> 16;
						long low = address.getOffset() & 0xffff;
						address = address.getNewAddress((high << 14) | (low & 0x3fff));
						makeReference(instr, address, refType);
						return true;
					}
				}
				return false;
			}

			// handle the reference on the correct read or write operand
			private void makeReference(Instruction instr, Address address, RefType refType) {
				int index = (refType.isRead() ? 1 : 0);
				instr.addOperandReference(index, address, refType, SourceType.ANALYSIS);
			}
		};

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}
}
