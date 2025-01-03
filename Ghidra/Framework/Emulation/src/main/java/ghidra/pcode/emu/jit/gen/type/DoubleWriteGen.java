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
package ghidra.pcode.emu.jit.gen.type;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType;
import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for writing doubles
 * 
 * <p>
 * This is accomplished by converting to a long and then writing it.
 */
public enum DoubleWriteGen implements TypedAccessGen {
	/** The big-endian instance */
	BE(LongWriteGen.BE),
	/** The little-endian instance */
	LE(LongWriteGen.LE);

	final LongWriteGen longGen;

	private DoubleWriteGen(LongWriteGen longGen) {
		this.longGen = longGen;
	}

	@Override
	public void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv) {
		TypeConversions.generateDoubleToLong(DoubleJitType.F8, LongJitType.forSize(vn.getSize()),
			rv);
		longGen.generateCode(gen, vn, rv);
	}
}
