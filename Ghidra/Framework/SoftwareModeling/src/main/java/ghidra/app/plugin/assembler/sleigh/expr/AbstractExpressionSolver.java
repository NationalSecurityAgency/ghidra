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

import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedConstructor;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * The root type of an expression solver
 * 
 * @param <T> the type of expression solved (the operator)
 */
public abstract class AbstractExpressionSolver<T extends PatternExpression> {
	private Class<T> tcls;
	protected RecursiveDescentSolver solver;

	protected final DbgTimer dbg = DbgTimer.INACTIVE;

	/**
	 * Construct a solver that can solve expression of the given type
	 * 
	 * @param tcls the type of expressions it can solve
	 */
	public AbstractExpressionSolver(Class<T> tcls) {
		this.tcls = tcls;
	}

	/**
	 * Attempt to solve an expression for a given value
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired value of the expression
	 * @param vals values of defined symbols
	 * @param res the results of subconstructor resolutions (used for lengths)
	 * @param hints describes techniques applied by calling solvers
	 * @param description the description to give to resolved solutions
	 * @return the resolution
	 * @throws NeedsBackfillException if the expression refers to an undefined symbol
	 */
	public abstract AssemblyResolution solve(T exp, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) throws NeedsBackfillException;

	/**
	 * Attempt to get a constant value for the expression
	 * 
	 * @param exp the expression
	 * @param vals values of defined symbols
	 * @param res the results of subconstructor resolutions (used for lengths)
	 * @return the constant value, or null if it depends on a variable
	 * @throws NeedsBackfillException if the expression refers to an undefined symbol
	 */
	public abstract MaskedLong getValue(T exp, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur) throws NeedsBackfillException;

	/**
	 * Determines the length of the subconstructor that would be returned had the expression not
	 * depended on an undefined symbol.
	 * 
	 * This is used by the backfilling process to ensure values are written to the correct offset
	 * 
	 * @param exp the expression
	 * @param res the results of subconstructor resolutions (used for lengths)
	 * @return the length of filled in token field(s).
	 */
	public abstract int getInstructionLength(T exp, Map<Integer, Object> res);

	/**
	 * Compute the value of the expression given the (possibly-intermediate) resolution
	 * 
	 * @param exp the expression to evaluate
	 * @param rc the resolution on which to evaluate it
	 * @return the result
	 */
	public abstract MaskedLong valueForResolution(T exp, AssemblyResolvedConstructor rc);

	/**
	 * Register this particular solver with the general expression solver
	 * 
	 * @param general the general solver
	 */
	protected void register(RecursiveDescentSolver general) {
		this.solver = general;
		general.register(tcls, this);
	}
}
