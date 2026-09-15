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
package ghidra.pcode.emu.jit.gen.access;

import ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType;
import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Local;
import ghidra.pcode.emu.jit.gen.util.Types.TDouble;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for accessing doubles
 * 
 * <p>
 * This is accomplished by delegating to the long access generator with type conversion.
 */
public enum DoubleAccessGen implements SimpleAccessGen<TDouble, DoubleJitType> {
	/** The big-endian instance */
	BE(LongAccessGen.BE),
	/** The little-endian instance */
	LE(LongAccessGen.LE);

	final LongAccessGen longGen;

	private DoubleAccessGen(LongAccessGen longGen) {
		this.longGen = longGen;
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TDouble>>
			genReadToStack(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					Varnode vn) {
		return em
				.emit(longGen::genReadToStack, localThis, gen, vn)
				.emit(LongToDouble.INSTANCE::convertStackToStack, LongJitType.I8, DoubleJitType.F8,
					Ext.ZERO);
	}

	@Override
	public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TDouble>>
			Emitter<N1> genWriteFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, Varnode vn) {
		return em
				.emit(DoubleToLong.INSTANCE::convertStackToStack, DoubleJitType.F8, LongJitType.I8,
					Ext.ZERO)
				.emit(longGen::genWriteFromStack, localThis, gen, vn);
	}
}
