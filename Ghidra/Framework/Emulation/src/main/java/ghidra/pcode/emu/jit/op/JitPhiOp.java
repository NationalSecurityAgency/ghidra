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
package ghidra.pcode.emu.jit.op;

import java.util.List;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.*;

/**
 * The synthetic use-def node for phi nodes.
 *
 * @param block the block containing the op that generated this phi node
 * @param out the use-def variable node for the output
 * @param options the map between block flows and options
 */
public record JitPhiOp(JitBlock block, JitOutVar out, BidiMap<BlockFlow, JitVal> options)
		implements JitDefOp, JitSyntheticOp {
	/**
	 * Construct a phi node without any options, yet.
	 * 
	 * @param block the block containing the op that generated this phi node
	 * @param out the use-def variable node for the output
	 */
	public JitPhiOp(JitBlock block, JitOutVar out) {
		this(block, out, new DualHashBidiMap<>());
	}

	/**
	 * Add an option assuming the given flow is taken
	 * 
	 * @param flow the flow
	 * @param option the option
	 */
	public void addOption(BlockFlow flow, JitVal option) {
		options.put(flow, option);
		option.addUse(this, 0); // HACK: 0 is as good as any position
	}

	/**
	 * Check if one of the options is an {@link JitInputVar input} to the passage.
	 * 
	 * @return true if an input option is present.
	 */
	public boolean hasInputOption() {
		return options.values().stream().anyMatch(opt -> opt instanceof JitInputVar);
	}

	/**
	 * Add the {@link JitInputVar input} option, if not already present
	 */
	public void addInputOption() {
		if (!hasInputOption()) {
			addOption(BlockFlow.entry(block), new JitInputVar(out.varnode()));
		}
	}

	@Override
	public void link() {
		JitDefOp.super.link();
		for (JitVal input : options.values()) {
			input.addUse(this, 0);
		}
	}

	@Override
	public void unlink() {
		JitDefOp.super.unlink();
		for (JitVal input : options.values()) {
			input.removeUse(this, 0);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote While this says I should care about some defined order, it's only so that the type
	 *           of each operand can be derived. They all take the {@link JitTypeBehavior#COPY copy}
	 *           type, so I'm not concerned.
	 */
	@Override
	public List<JitVal> inputs() {
		return List.copyOf(options.values());
	}

	@Override
	public JitTypeBehavior typeFor(int position) {
		if (position > options.size() || position < 0) {
			throw new AssertionError();
		}
		return optionType();
	}

	/**
	 * We do not require a particular type for the value, but we note the result is the same.
	 * 
	 * @return {@link JitTypeBehavior#COPY}
	 */
	public JitTypeBehavior optionType() {
		return JitTypeBehavior.COPY;
	}

	@Override
	public JitTypeBehavior type() {
		return JitTypeBehavior.COPY;
	}
}
