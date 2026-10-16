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
package ghidra.asm.wild.sem;

import java.util.Arrays;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.grammars.WildAssemblyProduction;
import ghidra.asm.wild.symbol.*;
import ghidra.asm.wild.tree.WildAssemblyParseHiddenNode;
import ghidra.asm.wild.tree.WildAssemblyParseToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class WildAssemblyTreeResolver
		extends AbstractAssemblyTreeResolver<WildAssemblyResolvedPatterns> {

	public WildAssemblyTreeResolver(
			AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, ?> factory,
			SleighLanguage lang, Address at, AssemblyParseBranch tree, AssemblyPatternBlock context,
			AssemblyContextGraph ctxGraph) {
		super(factory, lang, at, tree, context, ctxGraph);
	}

	protected AbstractAssemblyStateGenerator<?> getWildHiddenStateGenerator(OperandSymbol opSym,
			String wildcard, AssemblyResolvedPatterns fromLeft) {
		TripleSymbol defSym = opSym.getDefiningSymbol();
		if (defSym instanceof SubtableSymbol subtable) {
			return new WildAssemblyConstructStateGenerator(this, subtable, wildcard, fromLeft);
		}
		return new WildAssemblyNopStateGenerator(this, null, opSym, wildcard, fromLeft);
	}

	@Override
	protected AbstractAssemblyStateGenerator<?> getStateGenerator(OperandSymbol opSym,
			AssemblyParseTreeNode node, AssemblyResolvedPatterns fromLeft) {
		if (node instanceof WildAssemblyParseHiddenNode hidden) {
			return getWildHiddenStateGenerator(opSym, hidden.wildcard, fromLeft);
		}
		if (node instanceof AssemblyParseBranch branch && !branch.isConstructor()) {
			if (branch.getProduction() instanceof WildAssemblyProduction) {
				assert branch.getSubstitutions().size() == 1;
				return getStateGenerator(opSym, branch.getSubstitution(0), fromLeft);
			}
		}
		if (!(node instanceof WildAssemblyParseToken token)) {
			return super.getStateGenerator(opSym, node, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblySubtableTerminal term) {
			return getWildHiddenStateGenerator(opSym, token.wildcardName(), fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyNumericMapTerminal term) {
			return new WildAssemblyNumericMapStateGenerator(this, token, opSym, term.map, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyStringMapTerminal term) {
			return new WildAssemblyStringMapStateGenerator(this, token, opSym, term.map, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyStringTerminal term) {
			return new WildAssemblyStringStateGenerator(this, token, opSym, term.str, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyFixedNumericTerminal term) {
			return new WildAssemblyFixedNumericStateGenerator(this, token, opSym, term.val,
				fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyNumericTerminal term) {
			return new WildAssemblyNumericStateGenerator(this, token, opSym, token.wildcardName(),
				fromLeft);
		}
		return super.getStateGenerator(opSym, node, fromLeft);
	}

	/**
	 * Validate wildcard assembly results by disassembling representative concrete bytes.
	 *
	 * <p>
	 * The default resolver validates the pattern values directly, which means every unknown bit is
	 * supplied as zero. For wildcard-owned bits, zero can select a more-specific constructor than the
	 * one represented by the masked result, so this resolver uses wildcard-aware prototype check
	 * bytes without changing the returned resolution.
	 */
	@Override
	protected AssemblyResolutionResults filterByDisassembly(AssemblyResolutionResults temp) {
		AssemblyDefaultContext asmCtx = new AssemblyDefaultContext(lang);
		asmCtx.setContextRegister(context);
		AssemblyResolutionResults results = factory.newAssemblyResolutionResults();
		for (AssemblyResolution res : temp) {
			if (res.isError()) {
				results.add(res);
				continue;
			}
			if (!(res instanceof AssemblyResolvedPatterns rp)) {
				throw new AssertionError();
			}
			results.add(checkByDisassembly(rp, asmCtx));
		}
		return results;
	}

	/**
	 * Run the final disassembly prototype check for a resolved pattern.
	 *
	 * <p>
	 * The parsed prototype must still match the resolved constructor state. Only the temporary byte
	 * sequence used for parsing differs from the stored instruction pattern.
	 */
	protected AssemblyResolution checkByDisassembly(AssemblyResolvedPatterns rp,
			AssemblyDefaultContext asmCtx) {
		MemBuffer buf =
			new ByteMemBufferImpl(at, getPrototypeCheckBytes(rp), lang.isBigEndian());
		try {
			SleighInstructionPrototype ip =
				(SleighInstructionPrototype) lang.parse(buf, asmCtx, false);
			if (!rp.equivalentConstructState(ip.getRootState())) {
				return factory.error("Disassembly prototype mismatch", rp);
			}
			return rp;
		}
		catch (InsufficientBytesException | UnknownInstructionException e) {
			return factory.error("Disassembly failed: " + e.getMessage(), rp);
		}
	}

	/**
	 * Build the concrete byte sequence used only for prototype validation.
	 *
	 * <p>
	 * Fixed instruction bits are kept as-is. Unknown bits are set only when they belong to a wildcard
	 * operand location, which avoids validating wildcarded operands through zero-specialized
	 * constructors while preserving the original pattern masks and wildcard metadata.
	 */
	protected byte[] getPrototypeCheckBytes(AssemblyResolvedPatterns rp) {
		byte[] bytes = Arrays.copyOf(rp.getInstruction().getVals(),
			rp.getInstruction().getVals().length);
		byte[] instructionMask = rp.getInstruction().getMask();
		int instructionOffset = rp.getInstruction().getOffset();
		for (WildOperandInfo info : PatternUtils.castWild(rp).getOperandInfo()) {
			AssemblyPatternBlock location = info.location();
			byte[] locationMask = location.getMask();
			for (int i = 0; i < locationMask.length; i++) {
				int byteIndex = location.getOffset() + i - instructionOffset;
				if (byteIndex < 0 || byteIndex >= bytes.length) {
					continue;
				}
				int wildcardMask = locationMask[i] & 0xff;
				int specifiedMask = instructionMask[byteIndex] & 0xff;
				bytes[byteIndex] |= (byte) (wildcardMask & ~specifiedMask);
			}
		}
		return bytes;
	}
}
