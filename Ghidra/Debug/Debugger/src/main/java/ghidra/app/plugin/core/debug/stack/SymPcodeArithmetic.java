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
package ghidra.app.plugin.core.debug.stack;

import ghidra.app.plugin.core.debug.stack.Sym.ConstSym;
import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The interpretation of arithmetic p-code ops in the domain of {@link Sym} for a specific compiler
 * specification
 */
class SymPcodeArithmetic implements PcodeArithmetic<Sym> {

	private final Language language;
	private final CompilerSpec cSpec;

	/**
	 * Construct the arithmetic
	 * 
	 * @param cSpec the compiler specification
	 */
	public SymPcodeArithmetic(CompilerSpec cSpec) {
		this.cSpec = cSpec;
		this.language = cSpec.getLanguage();
	}

	@Override
	public Endian getEndian() {
		return language.isBigEndian() ? Endian.BIG : Endian.LITTLE;
	}

	@Override
	public Sym unaryOp(int opcode, int sizeout, int sizein1, Sym in1) {
		switch (opcode) {
			case PcodeOp.COPY:
				return in1;
			default:
				return Sym.opaque();
		}
	}

	@Override
	public Sym binaryOp(int opcode, int sizeout, int sizein1, Sym in1, int sizein2,
			Sym in2) {
		switch (opcode) {
			case PcodeOp.INT_ADD:
				return in1.add(cSpec, in2);
			case PcodeOp.INT_SUB:
				return in1.sub(cSpec, in2);
			default:
				return Sym.opaque();
		}
	}

	@Override
	public Sym modBeforeStore(int sizeout, int sizeinAddress, Sym inAddress,
			int sizeinValue, Sym inValue) {
		return inValue;
	}

	@Override
	public Sym modAfterLoad(int sizeout, int sizeinAddress, Sym inAddress,
			int sizeinValue, Sym inValue) {
		return inValue;
	}

	@Override
	public Sym fromConst(byte[] value) {
		return new ConstSym(Utils.bytesToLong(value, value.length, language.isBigEndian()),
			value.length);
	}

	@Override
	public byte[] toConcrete(Sym value, Purpose purpose) {
		if (value instanceof ConstSym constVal) {
			return Utils.longToBytes(constVal.value(), constVal.size(), language.isBigEndian());
		}
		throw new ConcretionError("Not a constant: " + value, purpose);
	}

	@Override
	public long sizeOf(Sym value) {
		return value.sizeOf(cSpec);
	}
}
