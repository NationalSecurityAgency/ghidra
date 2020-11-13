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
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedConstructor;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * This singleton class seeks solutions to {@link PatternExpression}s
 * 
 * It is called naive, because it does not perform algebraic transformations. Rather, it attempts to
 * fold constants, assuming there is a single variable in the expression, modifying the goal as it
 * descends toward that variable. If it finds a variable, i.e., token or context field, it encodes
 * the solution, positioned in the field. If the expression is constant, it checks that the goal
 * agrees. If not, an error is returned.
 * 
 * TODO This whole mechanism ought to just be factored directly into {@link PatternExpression}.
 */
public class RecursiveDescentSolver {
	protected static final DbgTimer dbg = DbgTimer.INACTIVE;
	private static final RecursiveDescentSolver solver = new RecursiveDescentSolver();

	// A mapping from each subclass of PatternExpression to the appropriate solver
	protected Map<Class<?>, AbstractExpressionSolver<?>> registry = new HashMap<>();

	{
		// Register all the solvers. Just one instance will do.
		new AndExpressionSolver().register(this);
		new ConstantValueSolver().register(this);
		new ContextFieldSolver().register(this);
		new DivExpressionSolver().register(this);
		new EndInstructionValueSolver().register(this);
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
		return solver;
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
	 * @param res resolved subconstructors, by operand index (see method details)
	 * @param hints describes techniques applied by calling solvers
	 * @param description a description to attached to the encoded solution
	 * @return the encoded solution
	 * @throws NeedsBackfillException a solution may exist, but a required symbol is missing
	 */
	protected AssemblyResolution solve(PatternExpression exp, MaskedLong goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			Set<SolverHint> hints, String description) throws NeedsBackfillException {
		try {
			return getRegistered(exp.getClass()).solve(exp, goal, vals, res, cur, hints,
				description);
		}
		catch (UnsupportedOperationException e) {
			dbg.println("Error solving " + exp + " = " + goal);
			throw e;
		}
	}

	/**
	 * Solve a given expression, assuming it outputs a given masked value
	 * 
	 * From a simplified perspective, we need only the expression and the desired value to solve it.
	 * Generally speaking, the expression may have only contain a single variable, and the encoded
	 * result represents that single variable. It must be absorbed into the overall instruction
	 * and/or context encoding.
	 * 
	 * More realistically, however, these expressions may depend on quite a bit of extra
	 * information. For example, PC-relative encodings (i.e., those involving {@code inst_start} or
	 * {@code inst_next}, need to know the starting address of the resulting instruction. {@code
	 * inst_start} must be provided to the solver by the assembler. {@code inst_next} cannot be
	 * known until the instruction length is known. Thus, expressions using it always result in a
	 * {@link NeedsBackfillException}. The symbols, when known, are provided to the solver via the
	 * {@code vals} parameter.
	 * 
	 * Expressions involving {@link OperandValueSolver}s are a little more complicated, because they
	 * specify an offset that affects its encoding in the instruction. To compute this offset, the
	 * lengths of other surrounding operands must be known. Thus, when solving a context change for
	 * a given constructor, its resolved subconstructors must be provided to the solver via the
	 * {@code res} parameter.
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired output (modulo a mask) of the expression
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @param res resolved subconstructors, by operand index (see method details)
	 * @param description a description to attached to the encoded solution
	 * @return the encoded solution
	 * @throws NeedsBackfillException a solution may exist, but a required symbol is missing
	 */
	public AssemblyResolution solve(PatternExpression exp, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, String description)
			throws NeedsBackfillException {
		return solve(exp, goal, vals, res, cur, Set.of(), description);
	}

	/**
	 * Attempt to fold a given expression (or sub-expression) into a single constant.
	 * 
	 * @param exp the (sub-)expression to fold
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @param res resolved subconstructors, by operand index (see
	 *        {@link #solve(PatternExpression, MaskedLong, Map, Map, AssemblyResolvedConstructor, String)})
	 * @return the masked solution
	 * @throws NeedsBackfillException it may be folded, but a required symbol is missing
	 */
	protected <T extends PatternExpression> MaskedLong getValue(T exp, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur)
			throws NeedsBackfillException {
		MaskedLong value = getRegistered(exp.getClass()).getValue(exp, vals, res, cur);
		dbg.println("Expression: " + value + " =: " + exp);
		return value;
	}

	/**
	 * Determine the length of the instruction part of the encoded solution to the given expression
	 * 
	 * This is used to keep operands in their appropriate position when backfilling becomes
	 * applicable. Normally, the instruction length is taken from the encoding of a solution, but if
	 * the solution cannot be determined yet, the instruction length must still be obtained.
	 * 
	 * The length can be determined by finding token fields in the expression.
	 * 
	 * @param exp the expression, presumably containing a token field
	 * @param res resolved subconstructors, by operand index (see
	 *            {@link #solve(PatternExpression, MaskedLong, Map, Map, AssemblyResolvedConstructor, String)})
	 * @return the anticipated length, in bytes, of the instruction encoding
	 */
	public int getInstructionLength(PatternExpression exp, Map<Integer, Object> res) {
		return getRegistered(exp.getClass()).getInstructionLength(exp, res);
	}

	/**
	 * Compute the value of an expression given a (possibly-intermediate) resolution
	 * 
	 * @param exp the expression to evaluate
	 * @param rc the resolution on which to evalute it
	 * @return the result
	 */
	public MaskedLong valueForResolution(PatternExpression exp, AssemblyResolvedConstructor rc) {
		return getRegistered(exp.getClass()).valueForResolution(exp, rc);
	}
}
