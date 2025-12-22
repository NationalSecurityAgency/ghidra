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
package ghidra.pcode.emu.jit.gen;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;
import static org.objectweb.asm.Opcodes.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.objectweb.asm.ClassVisitor;

import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class FieldForPcodeOp implements StaticFieldReq<TRef<PcodeOp>> {

	static String nameVn(Varnode vn) {
		if (vn == null) {
			return "null";
		}
		return "%s_%x_%d".formatted(vn.getAddress().getAddressSpace().getName(), vn.getOffset(),
			vn.getSize());
	}

	static String nameInputs(Varnode[] inputs) {
		return Stream.of(inputs).map(FieldForPcodeOp::nameVn).collect(Collectors.joining("__"));
	}

	private final PcodeOp op;
	private final FieldForVarnode outVnReq;
	private final List<FieldForVarnode> inVnReqs;

	public FieldForPcodeOp(JitCodeGenerator<?> gen, PcodeOp op) {
		this.op = op;

		this.outVnReq =
			op.getOutput() == null ? null : gen.requestStaticFieldForVarnode(op.getOutput());
		this.inVnReqs = Stream.of(op.getInputs()).map(gen::requestStaticFieldForVarnode).toList();
	}

	@Override
	public String name() {
		return "%s__%s__%s".formatted(nameVn(op.getOutput()), op.getMnemonic(),
			nameInputs(op.getInputs()));
	}

	@Override
	public <N extends Next> Emitter<N> genClInitCode(Emitter<N> em, JitCodeGenerator<?> gen,
			ClassVisitor cv) {
		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, GenConsts.T_PCODE_OP, name());

		var emIns = em
				.emit(gen::genAddress, op.getSeqnum().getTarget())
				.emit(Op::ldc__i, op.getSeqnum().getTime())
				.emit(Op::ldc__i, op.getOpcode())
				.emit(Op::ldc__i, op.getNumInputs())
				.emit(Op::anewarray, T_VARNODE);
		for (int i = 0; i < op.getNumInputs(); i++) {
			emIns = emIns
					.emit(Op::dup)
					.emit(Op::ldc__i, i)
					.emit(inVnReqs.get(i)::genLoad, gen)
					.emit(Op::aastore);
		}
		var emOut = outVnReq == null
				? emIns.emit(Op::aconst_null, T_VARNODE)
				: emIns.emit(outVnReq::genLoad, gen);
		return emOut
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "createOp",
					MDESC_JIT_COMPILED_PASSAGE__CREATE_OP, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::putstatic, gen.typeThis, name(), T_PCODE_OP);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TRef<PcodeOp>>> genLoad(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		return em
				.emit(Op::getstatic, gen.typeThis, name(), T_PCODE_OP);
	}
}
