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
package ghidra.pcode.emu.jit.decode;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.lifecycle.Internal;
import ghidra.pcode.emu.jit.folding.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.pcode.PcodeOp;

/**
 * An executor that simply records the ops that would be executed
 * <p>
 * This decodes instructions by delegating to another given executor
 */
@Internal
public class CollectExecutor extends PcodeExecutor<MaskedBytes> implements CanDecode {
	/**
	 * The collected ops
	 */
	public final List<PcodeOp> ops = new ArrayList<>();
	private final CanDecode delegate;

	/**
	 * Construct a collecting executor
	 * 
	 * @param language the language
	 * @param state the constant-folding state
	 * @param reason the reason for reading variables
	 * @param delegate the decoding delegate
	 */
	public CollectExecutor(SleighLanguage language, FoldedState state, Reason reason,
			CanDecode delegate) {
		super(language, FoldedArithmetic.forLanguage(language), state, reason);
		this.delegate = delegate;
	}

	/**
	 * Construct a collecting executor, based on a given executor
	 * 
	 * @param <T> the type of executor
	 * @param executor the executor
	 */
	public <T extends FoldingExecutor & CanDecode> CollectExecutor(T executor) {
		FoldedState state = executor.getState();
		this(executor.getLanguage(), state == null ? null : state.fork(), executor.getReason(),
			executor);
	}

	@Override
	public void stepOp(PcodeOp op, PcodeFrame frame,
			PcodeUseropLibrary<MaskedBytes> library) {
		ops.add(op);
	}

	@Override
	public PseudoInstruction decodeInstruction() {
		return delegate.decodeInstruction();
	}
}
