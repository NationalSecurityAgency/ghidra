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
package ghidra.pcode.emu.symz3;

import java.io.PrintStream;
import java.util.List;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Context;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.SleighInstructionDecoder;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.emu.auxiliary.AuxPcodeThread;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.emu.symz3.plain.SymZ3Space;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.symz3.model.SymValueZ3;

public class SymZ3PcodeThread extends AuxPcodeThread<SymValueZ3>
		implements InternalSymZ3RecordsPreconditions {
	public SymZ3PcodeThread(String name, AuxPcodeEmulator<SymValueZ3> emulator) {
		super(name, emulator);
	}

	@Override
	protected SleighInstructionDecoder createInstructionDecoder(
			PcodeExecutorState<Pair<byte[], SymValueZ3>> sharedState) {
		return new SleighInstructionDecoder(language, sharedState) {
			@Override
			public PseudoInstruction decodeInstruction(Address address, RegisterValue context) {
				PseudoInstruction instruction = super.decodeInstruction(address, context);
				addInstruction(instruction);
				return instruction;
			}
		};
	}

	@Override
	protected ThreadPcodeExecutorState<Pair<byte[], SymValueZ3>> createThreadState(
			PcodeExecutorState<Pair<byte[], SymValueZ3>> sharedState,
			PcodeExecutorState<Pair<byte[], SymValueZ3>> localState) {
		return new SymZ3ThreadPcodeExecutorState(sharedState, localState);
	}

	@Override
	public SymZ3ThreadPcodeExecutorState getState() {
		return (SymZ3ThreadPcodeExecutorState) super.getState();
	}

	public PcodeExecutorStatePiece<byte[], byte[]> getSharedConcreteState() {
		return getState().getSharedState().getLeft();
	}

	public AbstractSymZ3PcodeExecutorStatePiece<? extends SymZ3Space> getSharedSymbolicState() {
		return getState().getSharedState().getRight();
	}

	public PcodeExecutorStatePiece<byte[], byte[]> getLocalConcreteState() {
		return getState().getLocalState().getLeft();
	}

	public AbstractSymZ3PcodeExecutorStatePiece<? extends SymZ3Space> getLocalSymbolicState() {
		return getState().getLocalState().getRight();
	}

	@Override
	public void addPrecondition(String precondition) {
		getLocalSymbolicState().addPrecondition(precondition);
	}

	@Override
	public List<String> getPreconditions() {
		return getLocalSymbolicState().getPreconditions();
	}

	public void addInstruction(Instruction inst) {
		getSharedSymbolicState().addInstruction(this, inst);
	}

	public void addOp(PcodeOp op) {
		getSharedSymbolicState().addOp(this, op);
	}

	public void printRegisterComparison(PrintStream out, String reg) {
		ImmutablePair<String, String> p = registerComparison(reg);
		out.println(reg + " concrete: " + p.getLeft() + " whereas symbolic: " + p.getRight());
	}

	public ImmutablePair<String, String> registerComparison(String reg) {
		Register register = getLanguage().getRegister(reg);
		PcodeArithmetic<byte[]> concreteArithmetic = getLocalConcreteState().getArithmetic();
		long regValConcrete = concreteArithmetic
				.toLong(getLocalConcreteState().getVar(register, Reason.INSPECT), Purpose.INSPECT);
		SymValueZ3 regValSymbolic = getLocalSymbolicState().getVar(register, Reason.INSPECT);
		try (Context ctx = new Context()) {
			BitVecExpr bval = regValSymbolic.getBitVecExpr(ctx);
			BitVecExpr bvals = (BitVecExpr) bval.simplify();
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			return ImmutablePair.of(Long.toHexString(regValConcrete), z3p.infixUnsigned(bvals));
		}
	}

	public void printMemoryComparisonRegPlusOffset(PrintStream out, String reg, int offset) {
		ImmutablePair<String, String> p = memoryComparisonRegPlusOffset(reg, offset);
		out.println("MEM[" + reg + "+" + offset + "]" + " concrete: " + p.getLeft() +
			" whereas symbolic: " + p.getRight());
	}

	public ImmutablePair<String, String> memoryComparisonRegPlusOffset(String reg, int offset) {
		Language language = this.getLanguage();
		Register register = language.getRegister(reg);
		PcodeArithmetic<byte[]> concreteArithmetic = getSharedConcreteState().getArithmetic();
		long regValConcrete = concreteArithmetic
				.toLong(getLocalConcreteState().getVar(register, Reason.INSPECT), Purpose.INSPECT);
		SymValueZ3 regValSymbolic = getLocalSymbolicState().getVar(register, Reason.INSPECT);
		AddressSpace ram = this.language.getAddressFactory().getDefaultAddressSpace();
		Address concreteAddress = ram.getAddress(regValConcrete + offset);
		try (Context ctx = new Context()) {
			BitVecExpr bval = regValSymbolic.getBitVecExpr(ctx);
			long memValConcrete = concreteArithmetic.toLong(getSharedConcreteState()
					.getVar(concreteAddress, 1, false, Reason.INSPECT),
				Purpose.INSPECT);
			BitVecExpr bvals = (BitVecExpr) bval.simplify();
			SymValueZ3 offseteq =
				new SymValueZ3(ctx, ctx.mkBVAdd(bvals, ctx.mkBV(offset, bval.getSortSize())));
			SymValueZ3 memValSymbolic =
				getSharedSymbolicState().getVar(ram, offseteq, 1, false, Reason.INSPECT);
			BitVecExpr mv = memValSymbolic.getBitVecExpr(ctx);
			BitVecExpr mvs = (BitVecExpr) mv.simplify();
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			return ImmutablePair.of(Long.toString(memValConcrete, 16), z3p.infixUnsigned(mvs));
		}
	}
}
