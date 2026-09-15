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
package ghidra.app.plugin.core.debug.gui.emulation;

import ghidra.app.plugin.core.debug.gui.emulation.LocAndVal.LocAndValPcodeExecutorState;
import ghidra.app.plugin.core.debug.gui.emulation.LocAndVal.LocAndValPcodeExecutorStatePiece;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.pcode.Varnode;

// TODO: Consider using Varnode with defining op
// TODO: Consider compiling in the constructor? Would need language.
record VarStorageNode(String expr, Address address, int size) {
	static VarStorageNode fromVarnode(Varnode vn, CompilerSpec cSpec) {
		Address address = vn.getAddress();
		if (address.isStackAddress()) {
			return new VarStorageNode("*:%d (%s + 0x%x)".formatted(vn.getSize(),
				cSpec.getStackPointer(), address.getOffset()),
				cSpec.getStackBaseSpace().getAddress(0), vn.getSize());
		}
		if (address.isMemoryAddress()) {
			return new VarStorageNode("*:%d 0x%08x".formatted(vn.getSize(), vn.getOffset()),
				address, vn.getSize());
		}
		if (address.isRegisterAddress()) {
			return new VarStorageNode(vn.toString(cSpec.getLanguage()), address, vn.getSize());
		}
		if (address.isUniqueAddress()) {
			return new VarStorageNode("$Unique", address, vn.getSize());
		}
		throw new AssertionError();
	}

	static VarStorageNode fromExpression(SleighLanguage language, String expression) {
		PcodeExpression expr = SleighProgramCompiler.compileExpression(language, expression);
		LocAndValPcodeExecutorState state =
			new LocAndValPcodeExecutorState(new LocAndValPcodeExecutorStatePiece(
				new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE),
				new LocationPcodeExecutorStatePiece(language)));
		PcodeExecutor<LocAndVal> exec = new PcodeExecutor<LocAndVal>(state, Reason.INSPECT);
		ValueLocation loc = expr.evaluate(exec).loc();
		return new VarStorageNode(expression, loc.getAddress(), loc.size());
	}

	PcodeExpression compile(SleighLanguage language) {
		return SleighProgramCompiler.compileExpression(language, expr);
	}

	@Override
	public final String toString() {
		return expr;
	}

	public VarStorageNode deref(SleighLanguage language, AddressSpace space, int length) {
		String derefExpr = space == language.getDefaultDataSpace()
				? "*:%d (%s)".formatted(length, expr)
				: "*[%s]:%d (%s)".formatted(space.getName(), length, expr);
		return new VarStorageNode(derefExpr, space.getAddress(0), length);
	}

	public VarStorageNode deref(SleighLanguage language, AddressSpace space, int offset,
			int length) {
		String derefExpr = space == language.getDefaultDataSpace()
				? "*:%d ((%s)+%d)".formatted(length, expr, offset)
				: "*[%s]:%d ((%s)+%d)".formatted(space.getName(), length, expr, offset);
		return new VarStorageNode(derefExpr, space.getAddress(0), length);
	}
}
