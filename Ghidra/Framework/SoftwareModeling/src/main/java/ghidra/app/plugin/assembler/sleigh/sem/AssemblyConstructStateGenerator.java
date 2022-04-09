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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.*;
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;
import ghidra.app.plugin.assembler.sleigh.util.AsmUtil;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

/**
 * The generator of {@link AssemblyConstructState} from {@link AssemblyParseBranch}
 * 
 * <p>
 * In short, this handles the selection of each possible constructor for the production recorded by
 * a given parse branch.
 */
public class AssemblyConstructStateGenerator
		extends AbstractAssemblyStateGenerator<AssemblyParseBranch> {

	/**
	 * Construct the instruction state generator or a sub-table operand state generator
	 * 
	 * @param resolver the resolver
	 * @param node the node from which to generate states
	 * @param fromLeft the accumulated patterns from the left sibling or the parent
	 */
	public AssemblyConstructStateGenerator(AssemblyTreeResolver resolver, AssemblyParseBranch node,
			AssemblyResolvedPatterns fromLeft) {
		super(resolver, node, fromLeft);
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		AssemblyProduction production = node.getProduction();
		return resolver.grammar.getSemantics(production)
				.stream()
				.flatMap(sem -> applyConstructor(gc, sem));
	}

	/**
	 * Arrange the branch's (mnemonic) children according to the machine-code production
	 * 
	 * <p>
	 * This orders the parsed children so that each is readily paired to its operand as given by
	 * {@link Constructor#getOperand(int)}.
	 * 
	 * @param sem the SLEIGH constructor whose machine-code production to consider
	 * @return the children arranged in constructor operand order
	 */
	protected List<AssemblyParseTreeNode> orderOpNodes(AssemblyConstructorSemantic sem) {
		Constructor cons = sem.getConstructor();
		List<AssemblyParseTreeNode> result =
			Arrays.asList(new AssemblyParseTreeNode[cons.getNumOperands()]);
		int index = 0;
		AssemblyProduction production = node.getProduction();
		List<AssemblyParseTreeNode> substitutions = node.getSubstitutions();
		for (int i = 0; i < production.getRHS().size(); i++) {
			AssemblySymbol sym = production.getRHS().getSymbol(i);
			if (!sym.takesOperandIndex()) {
				continue;
			}
			result.set(sem.getOperandIndex(index), substitutions.get(i));
			index++;
		}
		return result;
	}

	/**
	 * Generate prototypes, considering the given SLEIGH constructor
	 * 
	 * <p>
	 * This comprises three steps: apply patterns, apply context changes, apply operands
	 * left-to-right.
	 * 
	 * @param gc the generator context for this node
	 * @param sem the SLEIGH constructor to apply
	 * @return the stream of generated (sub) prototypes
	 */
	protected Stream<AssemblyGeneratedPrototype> applyConstructor(GeneratorContext gc,
			AssemblyConstructorSemantic sem) {
		Stream<AssemblyResolvedPatterns> applied = sem.applyPatternsForward(gc.shift, fromLeft)
				.filter(pat -> {
					if (pat == null) {
						gc.dbg("Conflicting pattern. fromLeft=" + fromLeft + ",sem=" +
							sem.getLocation());
						return false;
					}
					return true;
				})
				.map(pat -> sem.applyContextChangesForward(resolver.vals, pat));
		List<AssemblyParseTreeNode> opOrdered = orderOpNodes(sem);
		return applied.flatMap(
			patterned -> applyOperands(gc, patterned, sem, opOrdered));
	}

	/**
	 * Generate prototypes by considering all the operands of the given SLEIGH constructor
	 * 
	 * <p>
	 * This is the last step of applying a constructor.
	 * 
	 * @param gc the generator context for this node
	 * @param fromMutations the patterns as accumulated after context changes
	 * @param sem the selected SLEIGH constructor
	 * @param opOrdered the parsed children ordered as the constructor's operands
	 * @return the stream of generated (sub) prototypes
	 */
	protected Stream<AssemblyGeneratedPrototype> applyOperands(GeneratorContext gc,
			AssemblyResolvedPatterns fromMutations, AssemblyConstructorSemantic sem,
			List<AssemblyParseTreeNode> opOrdered) {
		Constructor cons = sem.getConstructor();
		List<GeneratorContext> siblingGcs =
			Arrays.asList(new GeneratorContext[cons.getNumOperands()]);
		return applyRemainingOperands(gc, siblingGcs, fromMutations, sem, opOrdered, List.of());
	}

	/**
	 * A recursive function for generating child operand prototypes and constructing the parent(s)
	 * 
	 * <p>
	 * The implementation generates states for the left-most node not yet considered. It knows which
	 * is next by examining the length of {@code children}, which records the generated state for
	 * each child already considered. It then appends the result to {@code children} and recurses,
	 * using the resulting patterns as {@code fromLeft}. Given that multiple prototypes can be
	 * generated, {@link Stream#flatMap(java.util.function.Function)} makes the recursive invocation
	 * somewhat fluent. The base case occurs when all children have states generated. It constructs
	 * the state for this node, storing the generated children with it.
	 * 
	 * <p>
	 * This routine is also operative in computing shifts, since the offset of each operand is
	 * incorporated here. Two accessors are needed to compute the offset:
	 * {@link OperandSymbol#getOffsetBase()} and {@link OperandSymbol#getRelativeOffset()}. The
	 * former identifies which operand's end (exclusive) byte is the base of the offset. The latter
	 * specifies an additional number of bytes to the right. Consider an operand consisting of three
	 * operands, each consuming a 1-byte token.
	 * 
	 * <pre>
	 * +-----+-----+-----+
	 * | op0 | op1 | op2 |
	 * +-----+-----+-----+
	 *  ^-1   ^0    ^1    ^2
	 * </pre>
	 * 
	 * <p>
	 * A base offset of 0 would indicate that the overall offset is the end of op0 (relative to the
	 * parent op) plus the relative offset. A base offset of -1 is special, but is easy to
	 * conceptualize from the diagram. It indicates the beginning byte of the parent op. Thus every
	 * child operand boundary is numbered. The offset base must always refer to an operand to the
	 * left.
	 * 
	 * @param parentGc the generator context for othis node
	 * @param childGcs a list to collect the generator context for each child operand. The root
	 *            invocation should pass a fixed-length mutable list of nulls, one for each child.
	 * @param fromLeft the accumulated patterns from the left sibling. The root invocation should
	 *            pass the patterns accumulated after context changes.
	 * @param sem the selected SLEIGH constructor, whose operands to generate
	 * @param opOrdered the paresd children ordered as the constructor's operands
	 * @param children the list of children generated so far. The root invocation should pass the
	 *            empty list.
	 * @return the stream of generated (sub) prototypes
	 */
	protected Stream<AssemblyGeneratedPrototype> applyRemainingOperands(GeneratorContext parentGc,
			List<GeneratorContext> childGcs, AssemblyResolvedPatterns fromLeft,
			AssemblyConstructorSemantic sem, List<AssemblyParseTreeNode> opOrdered,
			List<AbstractAssemblyState> children) {
		Constructor cons = sem.getConstructor();
		int opIdx = children.size();
		if (opIdx == cons.getNumOperands()) {
			// We're done!
			return Stream.of(new AssemblyGeneratedPrototype(
				new AssemblyConstructState(resolver, parentGc.path, parentGc.shift, sem, children),
				fromLeft));
		}
		AssemblyParseTreeNode opNode = opOrdered.get(opIdx);
		OperandSymbol opSym = cons.getOperand(opIdx);
		int offset = opSym.getRelativeOffset();
		int offsetBase = opSym.getOffsetBase();
		if (-1 != offsetBase) {
			int baseShift = childGcs.get(offsetBase).shift;
			int baseLength = children.get(offsetBase).getLength();
			offset += baseShift - parentGc.shift + baseLength;
		}

		AbstractAssemblyStateGenerator<?> opGen =
			resolver.getStateGenerator(opSym, opNode, fromLeft);
		GeneratorContext opGc = parentGc.push(sem, offset);
		childGcs.set(opIdx, opGc);
		return opGen.generate(opGc).flatMap(prot -> {
			return applyRemainingOperands(parentGc, new ArrayList<>(childGcs), prot.patterns, sem,
				opOrdered, AsmUtil.extendList(children, prot.state));
		});
	}
}
