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

import ghidra.pcode.emu.jit.analysis.JitType.FloatJitType;
import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Local;
import ghidra.pcode.emu.jit.gen.util.Types.TFloat;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for writing floats
 * 
 * <p>
 * This is accomplished by delegating to the int access generator with type conversion.
 */
public enum FloatAccessGen implements SimpleAccessGen<TFloat, FloatJitType> {
	/** The big-endian instance */
	BE(IntAccessGen.BE),
	/** The little-endian instance */
	LE(IntAccessGen.LE);

	final IntAccessGen intGen;

	private FloatAccessGen(IntAccessGen intGen) {
		this.intGen = intGen;
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TFloat>> genReadToStack(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Varnode vn) {
		return em
				.emit(intGen::genReadToStack, localThis, gen, vn)
				.emit(IntToFloat.INSTANCE::convertStackToStack, IntJitType.I4, FloatJitType.F4,
					Ext.ZERO);
	}

	@Override
	public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TFloat>>
			Emitter<N1> genWriteFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, Varnode vn) {
		return em
				.emit(FloatToInt.INSTANCE::convertStackToStack, FloatJitType.F4, IntJitType.I4,
					Ext.ZERO)
				.emit(intGen::genWriteFromStack, localThis, gen, vn);
	}
}
