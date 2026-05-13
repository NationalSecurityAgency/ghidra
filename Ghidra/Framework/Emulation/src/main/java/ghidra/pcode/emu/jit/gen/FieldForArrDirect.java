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

import static org.objectweb.asm.Opcodes.ACC_FINAL;
import static org.objectweb.asm.Opcodes.ACC_PRIVATE;

import org.objectweb.asm.ClassVisitor;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.address.Address;

/**
 * A field request for a pre-fetched page from the {@link JitBytesPcodeExecutorStateSpace}.
 * 
 * <p>
 * The field is used for direct memory accesses. For those, the address space and fixed address is
 * given in the p-code, so we are able to pre-fetch the page and access it directly at run time.
 * 
 * @param address the address contained by the page to pre-fetch
 */
public record FieldForArrDirect(Address address) implements InstanceFieldReq<TRef<byte[]>> {
	@Override
	public String name() {
		return "arrDir_%s_%x".formatted(address.getAddressSpace().getName(),
			address.getOffset());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the address {@code ram:00600000}. The declaration is equivalent to:
	 * 
	 * <pre>
	 * private final byte[] arrDir_ram_600000;
	 * </pre>
	 * 
	 * <p>
	 * And the initialization is equivalent to:
	 * 
	 * <pre>
	 * arrDir_ram_600000 =
	 * 	state.getForSpace(ADDRESS_FACTORY.getAddressSpace(ramId)).getDirect(0x600000);
	 * </pre>
	 */
	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, ClassVisitor cv) {
		Fld.decl(cv, ACC_PRIVATE | ACC_FINAL, Types.T_BYTE_ARR, name());
		return em
				.emit(Op::aload, localThis)
				.emit(gen::genLoadJitStateSpace, localThis, address.getAddressSpace())
				.emit(Op::ldc__l, address.getOffset())
				.emit(Op::invokevirtual, GenConsts.T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE,
					"getDirect", GenConsts.MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__GET_DIRECT,
					false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::putfield, gen.typeThis, name(), Types.T_BYTE_ARR);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<byte[]>>>
			genLoad(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
		return em
				.emit(Op::aload, localThis)
				.emit(Op::getfield, gen.typeThis, name(), Types.T_BYTE_ARR);
	}
}
