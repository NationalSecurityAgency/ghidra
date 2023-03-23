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
package ghidra.app.plugin.assembler.sleigh.expr;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * This singleton class seeks solutions to {@link PatternExpression}s
 * 
 * <p>
 * It is rather naive. It does not perform algebraic transformations. Instead, it attempts to fold
 * constants, assuming there is a single variable in the expression, modifying the goal as it
 * descends toward that variable. If it finds a variable, i.e., token or context field, it encodes
 * the solution, positioned in the field. If the expression is constant, it checks that the goal
 * agrees. If not, an error is returned. There are some common cases where it is forced to solve
 * expressions involving multiple variables. Those cases are addressed in the derivatives of
 * {@link AbstractBinaryExpressionSolver} where the situation can be detected. One common example is
 * field concatenation using the {@code (A << 4) | B} pattern.
 * 
 * <p>
 * TODO: Perhaps this whole mechanism ought to just be factored directly into
 * {@link PatternExpression}.
 */
public class RecursiveDescentSolver {
	protected static final DbgTimer DBG = DbgTimer.INACTIVE;
	private static final RecursiveDescentSolver INSTANCE = new RecursiveDescentSolver();

	// A mapping from each subclass of PatternExpression to the appropriate solver
	protected Map<Class<?>, AbstractExpressionSolver<?>> registry = new HashMap<>();

	{
		// Register all the solvers. Just one instance will do.
		new AndExpressionSolver().register(this);
		new ConstantValueSolver().register(this);
		new ContextFieldSolver().register(this);
		new DivExpressionSolver().register(this);
		new EndInstructionValueSolver().register(this);
		new Next2InstructionValueSolver().register(this);
		new LeftShiftExpressionSolver().register(this);
		new MinusExpressionSolver().register(this);
		new MultExpressionSolver().register(this);
		new NotExpressionSolver().register(this);
		new OperandValueSolver().register(this);
		new OrExpressionSolver().register(this);
		new PlusExpressionSolver().register(this);
		new RightShiftExpressionSolver().register(this);
		new StartInstructionValueSolver().register(this);
		new SubExpressionSolver().register(this);
		new TokenFieldSolver().register(this);
		new XorExpressionSolver().register(this);
	}

	/**
	 * Obtain an instance of the naive solver
	 * 
	 * @return the singleton instance
	 */
	public static RecursiveDescentSolver getSolver() {
		return INSTANCE;
	}

	/**
	 * Register a solver for a particular subclass of {@link PatternExpression}
	 * 
	 * @param tcls the subclass the solver can handle
	 * @param s the solver for the subclass
	 */
	protected <T extends PatternExpression> void register(Class<T> tcls,
			AbstractExpressionSolver<T> s) {
		registry.put(tcls, s);
	}

	/**
	 * Retrieve the registered solver for a given subclass of {@link PatternExpression}
	 * 
	 * @param tcls the subclass to solve
	 * @return the registered solver
	 */
	protected <T extends PatternExpression> AbstractExpressionSolver<T> getRegistered(
			Class<?> tcls) {
		@SuppressWarnings("unchecked")
		AbstractExpressionSolver<T> s = (AbstractExpressionSolver<T>) registry.get(tcls);
		if (s == null) {
			throw new RuntimeException("No registered solver for class " + tcls);
		}
		return s;
	}

	/**
	 * Solve a given expression, passing hints
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired output (modulo a mask) of the expression
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @param hints describes techniques applied by calling solvers
	 * @param description a description to attached to the encoded solution
	 * @return the encoded solution
	 * @throws NeedsBackfillException a solution may exist, but a required symbol is missing
	 */
	protected AssemblyResolution solve(PatternExpression exp, MaskedLong goal,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, Set<SolverHint> hints,
			String description) throws NeedsBackfillException {
		try {
			return getRegistered(exp.getClass()).solve(exp, goal, vals, cur, hints, description);
		}
		catch (UnsupportedOperationException e) {
			DBG.println("Error solving " + exp + " = " + goal);
			throw e;
		}
	}

	/**
	 * Solve a given expression, given a masked-value goal
	 * 
	 * <p>
	 * From a simplified perspective, we need only the expression and the desired value to solve it.
	 * Generally speaking, the expression may only contain a single field, and the encoded result
	 * specifies the bits of the solved field. It must be absorbed into the overall assembly
	 * pattern.
	 * 
	 * <p>
	 * More realistically, these expressions may depend on quite a bit of extra information. For
	 * example, PC-relative encodings (i.e., those involving {@code inst_start} or
	 * {@code inst_next}, need to know the starting address of the resulting instruction. {@code
	 * inst_start} must be provided to the solver by the assembler. {@code inst_next} cannot be
	 * known until the instruction length is known. Thus, expressions using it always result in a
	 * {@link NeedsBackfillException}. The symbols, when known, are provided to the solver via the
	 * {@code vals} parameter.
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired output (modulo a mask) of the expression
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @param description a description to attached to the encoded solution
	 * @return the encoded solution
	 * @throws NeedsBackfillException a solution may exist, but a required symbol is missing
	 */
	public AssemblyResolution solve(PatternExpression exp, MaskedLong goal, Map<String, Long> vals,
			AssemblyResolvedPatterns cur, String description)
			throws NeedsBackfillException {
		return solve(exp, goal, vals, cur, Set.of(), description);
	}

	/**
	 * Attempt to fold a given expression (or sub-expression) into a single constant.
	 * 
	 * @param exp the (sub-)expression to fold
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @return the masked solution
	 * @throws NeedsBackfillException it may be folded, but a required symbol is missing
	 */
	protected <T extends PatternExpression> MaskedLong getValue(T exp, Map<String, Long> vals,
			AssemblyResolvedPatterns cur) throws NeedsBackfillException {
		MaskedLong value = getRegistered(exp.getClass()).getValue(exp, vals, cur);
		DBG.println("Expression: " + value + " =: " + exp);
		return value;
	}

	/**
	 * Determine the length of the instruction part of the encoded solution to the given expression
	 * 
	 * <p>
	 * This is used to keep operands in their appropriate position when backfilling becomes
	 * applicable. Normally, the instruction length is taken from the encoding of a solution, but if
	 * the solution cannot be determined yet, the instruction length must still be obtained.
	 * 
	 * <p>
	 * The length can be determined by finding token fields in the expression.
	 * 
	 * @param exp the expression, presumably containing a token field
	 * @return the anticipated length, in bytes, of the instruction encoding
	 */
	public int getInstructionLength(PatternExpression exp) {
		return getRegistered(exp.getClass()).getInstructionLength(exp);
	}

	/**
	 * Compute the value of an expression given a (possibly-intermediate) resolution
	 * 
	 * @param exp the expression to evaluate
	 * @param vals values of defined symbols
	 * @param rc the resolution on which to evaluate it
	 * @return the result
	 */
	public MaskedLong valueForResolution(PatternExpression exp, Map<String, Long> vals,
			AssemblyResolvedPatterns rc) {
		return getRegistered(exp.getClass()).valueForResolution(exp, vals, rc);
	}
}
