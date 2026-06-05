/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.util.*;
import java.util.function.Predicate;

import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.lisa.pcode.statements.PcodeUnaryOperator;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.Satisfiability;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.stability.Trend;
import it.unive.lisa.analysis.value.ValueDomain;
import it.unive.lisa.program.SyntheticLocation;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.SymbolicExpression;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.symbolic.value.operator.binary.*;
import it.unive.lisa.util.representation.ObjectRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * Implementation of the stability abstract domain (yet to appear publicly).
 * This domain computes per-variable numerical trends to infer stability,
 * covariance and contravariance relations on program variables, exploiting an
 * auxiliary domain of choice. This is implemented as an open product where the
 * stability domain gathers information from the auxiliary one through boolean
 * queries.<br>
 * <br>
 * Implementation-wise, this class is built as a product between a given
 * {@link ValueDomain} {@code aux} and a {@link ValueEnvironment} {@code trends}
 * of {@link Trend} instances, representing per-variable trends. Queries are
 * carried over by the
 * {@link SemanticDomain#satisfies(SymbolicExpression, ProgramPoint, SemanticOracle)}
 * operator invoked on {@code aux}.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 * 
 * @param <V> the kind of auxiliary domain
 */
public class PcodeStability<V extends ValueDomain<V>>
		implements
		BaseLattice<PcodeStability<V>>,
		ValueDomain<PcodeStability<V>> {

	private final V aux;

	private final ValueEnvironment<Trend> trends;

	/**
	 * Builds the top stability domain, using {@code aux} as auxiliary domain.
	 * 
	 * @param aux the auxiliary domain
	 */
	public PcodeStability(
			V aux) {
		this.aux = aux.top();
		this.trends = new ValueEnvironment<>(Trend.TOP);
	}

	/**
	 * Builds a stability domain instance, using {@code aux} as auxiliary
	 * domain.
	 * 
	 * @param aux    the auxiliary domain
	 * @param trends the existing per-variable trend information
	 */
	public PcodeStability(
			V aux,
			ValueEnvironment<Trend> trends) {
		this.aux = trends.isBottom() ? aux.bottom() : aux;
		this.trends = aux.isBottom() ? trends.bottom() : trends;
	}

	@Override
	public PcodeStability<V> lubAux(
			PcodeStability<V> other)
			throws SemanticException {
		V ad = aux.lub(other.aux);
		ValueEnvironment<Trend> t = trends.lub(other.trends);
		if (ad.isBottom() || t.isBottom()) {
			return bottom();
		}
		return new PcodeStability<>(ad, t);
	}

	@Override
	public PcodeStability<V> glbAux(
			PcodeStability<V> other)
			throws SemanticException {
		V ad = aux.glb(other.aux);
		ValueEnvironment<Trend> t = trends.glb(other.trends);
		if (ad.isBottom() || t.isBottom()) {
			return bottom();
		}
		return new PcodeStability<>(ad, t);
	}

	@Override
	public PcodeStability<V> wideningAux(
			PcodeStability<V> other)
			throws SemanticException {
		V ad = aux.widening(other.aux);
		ValueEnvironment<Trend> t = trends.widening(other.trends);
		if (ad.isBottom() || t.isBottom()) {
			return bottom();
		}
		return new PcodeStability<>(ad, t);
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeStability<V> other)
			throws SemanticException {
		return aux.lessOrEqual(other.aux) && trends.lessOrEqual(other.trends);
	}

	@Override
	public boolean isTop() {
		return aux.isTop() && trends.isTop();
	}

	@Override
	public boolean isBottom() {
		return aux.isBottom() || trends.isBottom();
	}

	@Override
	public PcodeStability<V> top() {
		return new PcodeStability<>(aux.top(), trends.top());
	}

	@Override
	public PcodeStability<V> bottom() {
		return new PcodeStability<>(aux.bottom(), trends.bottom());
	}

	@Override
	public PcodeStability<V> pushScope(
			ScopeToken token)
			throws SemanticException {
		return new PcodeStability<>(aux.pushScope(token), trends.pushScope(token));
	}

	@Override
	public PcodeStability<V> popScope(
			ScopeToken token)
			throws SemanticException {
		return new PcodeStability<>(aux.popScope(token), trends.popScope(token));
	}

	/**
	 * Yields {@code true} if the {@code aux.satisfies(query, pp, oracle)}
	 * returns {@link Satisfiability#SATISFIED}.
	 * 
	 * @param query  the query to execute
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@code true} if the query is always satisfied
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private boolean query(
			BinaryExpression query,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return aux.satisfies(query, pp, oracle) == Satisfiability.SATISFIED;
	}

	/**
	 * Builds a {@link BinaryExpression} in the form of "l operator r".
	 * 
	 * @param operator the {@link BinaryOperator} to apply
	 * @param l        the left operand
	 * @param r        the right operand
	 * @param pp       the {@link ProgramPoint} where the expression is being
	 *                     built
	 *
	 * @return the new BinaryExpression
	 */
	private BinaryExpression binary(
			BinaryOperator operator,
			SymbolicExpression l,
			SymbolicExpression r,
			ProgramPoint pp) {
		return new BinaryExpression(
			pp.getProgram().getTypes().getBooleanType(),
			l,
			r,
			operator,
			SyntheticLocation.INSTANCE);
	}

	/**
	 * Builds a {@link Constant} with value {@code c}.
	 *
	 * @param c  the integer constant
	 * @param pp the {@link ProgramPoint} where the expression is being built
	 * 
	 * @return the new Constant
	 */
	private Constant constantInt(
			int c,
			ProgramPoint pp) {
		return new Constant(
			pp.getProgram().getTypes().getIntegerType(),
			c,
			SyntheticLocation.INSTANCE);
	}

	/**
	 * Generates a {@link Trend} based on the relationship between {@code a} and
	 * {@code b} in {@link #aux}.
	 * 
	 * @param a      the first expression
	 * @param b      the second expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#INC} if {@code a > b}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend increasingIfGreater(
			SymbolicExpression a,
			SymbolicExpression b,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (query(binary(ComparisonEq.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.STABLE;
		}
		else if (query(binary(ComparisonGt.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.INC;
		}
		else if (query(binary(ComparisonGe.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.NON_DEC;
		}
		else if (query(binary(ComparisonLt.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.DEC;
		}
		else if (query(binary(ComparisonLe.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.NON_INC;
		}
		else if (query(binary(ComparisonNe.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.NON_STABLE;
		}
		else {
			return Trend.TOP;
		}
	}

	/**
	 * Generates a {@link Trend} based on the relationship between {@code a} and
	 * {@code b} in {@link #aux}.
	 * 
	 * @param a      the first expression
	 * @param b      the second expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#INC} if {@code a < b}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend increasingIfLess(
			SymbolicExpression a,
			SymbolicExpression b,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return increasingIfGreater(a, b, pp, oracle).invert();
	}

	/**
	 * Generates a {@link Trend} based on the relationship between {@code a} and
	 * {@code b} in {@link #aux}.
	 * 
	 * @param a      the first expression
	 * @param b      the second expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#NON_DEC} if {@code a > b}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend nonDecreasingIfGreater(
			SymbolicExpression a,
			SymbolicExpression b,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (query(binary(ComparisonEq.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.STABLE;
		}
		else if (query(binary(ComparisonGt.INSTANCE, a, b, pp), pp, oracle) ||
			query(binary(ComparisonGe.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.NON_DEC;
		}
		else if (query(binary(ComparisonLt.INSTANCE, a, b, pp), pp, oracle) ||
			query(binary(ComparisonLe.INSTANCE, a, b, pp), pp, oracle)) {
			return Trend.NON_INC;
		}
		else {
			return Trend.TOP;
		}
	}

	/**
	 * Generates a {@link Trend} based on the relationship between {@code a} and
	 * {@code b} in {@link #aux}.
	 * 
	 * @param a      the first expression
	 * @param b      the second expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#NON_DEC} if {@code a < b}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend nonDecreasingIfLess(
			SymbolicExpression a,
			SymbolicExpression b,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return nonDecreasingIfGreater(a, b, pp, oracle).invert();
	}

	/**
	 * Generates a {@link Trend} based on the relationship between {@code a} and
	 * {@code b} in {@link #aux}.
	 * 
	 * @param a      the expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#INC} if {@code 0 < a < 1 || 0 <= a < 1}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend increasingIfBetweenZeroAndOne(
			SymbolicExpression a,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		Constant zero = constantInt(0, pp);
		Constant one = constantInt(1, pp);

		if (query(binary(ComparisonEq.INSTANCE, a, zero, pp), pp, oracle) ||
			query(binary(ComparisonEq.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.STABLE;
		}
		else if (query(binary(ComparisonGt.INSTANCE, a, zero, pp), pp, oracle) &&
			query(binary(ComparisonLt.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.INC;
		}
		else if (query(binary(ComparisonGe.INSTANCE, a, zero, pp), pp, oracle) &&
			query(binary(ComparisonLe.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.NON_DEC;
		}
		else if (query(binary(ComparisonLt.INSTANCE, a, zero, pp), pp, oracle) &&
			query(binary(ComparisonGt.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.DEC;
		}
		else if (query(binary(ComparisonLe.INSTANCE, a, zero, pp), pp, oracle) &&
			query(binary(ComparisonGe.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.NON_INC;
		}
		else if (query(binary(ComparisonNe.INSTANCE, a, zero, pp), pp, oracle) &&
			query(binary(ComparisonNe.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.NON_STABLE;
		}
		else {
			return Trend.TOP;
		}
	}

	/**
	 * Generates a {@link Trend} based on the value of {@code a} in
	 * {@link #aux}.
	 * 
	 * @param a      the expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#INC} if {@code a < 0 || a > 1}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend increasingIfOutsideZeroAndOne(
			SymbolicExpression a,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return increasingIfBetweenZeroAndOne(a, pp, oracle).invert();
	}

	/**
	 * Generates a {@link Trend} based on the value of {@code a} in
	 * {@link #aux}.
	 * 
	 * @param a      the expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#NON_DEC} if {@code 0 < a < 1 || 0 <= a < 1}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend nonDecreasingIfBetweenZeroAndOne(
			SymbolicExpression a,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		Constant zero = constantInt(0, pp);
		Constant one = constantInt(1, pp);

		if (query(binary(ComparisonEq.INSTANCE, a, zero, pp), pp, oracle) ||
			query(binary(ComparisonEq.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.STABLE;
		}
		else if (query(binary(ComparisonGe.INSTANCE, a, zero, pp), pp, oracle) &&
			query(binary(ComparisonLe.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.NON_DEC;
		}
		else if (query(binary(ComparisonLe.INSTANCE, a, zero, pp), pp, oracle) ||
			query(binary(ComparisonGe.INSTANCE, a, one, pp), pp, oracle)) {
			return Trend.NON_INC;
		}
		else {
			return Trend.TOP;
		}
	}

	/**
	 * Generates a {@link Trend} based on the value of {@code a} in
	 * {@link #aux}.
	 * 
	 * @param a      the expression
	 * @param pp     the {@link ProgramPoint} where the evaluation happens
	 * @param oracle the oracle for inter-domain communication
	 * 
	 * @return {@link Trend#NON_DEC} if {@code a < 0 || a > 1}
	 * 
	 * @throws SemanticException if something goes wrong during the evaluation
	 */
	private Trend nonDecreasingIfOutsideZeroAndOne(
			SymbolicExpression a,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return nonDecreasingIfBetweenZeroAndOne(a, pp, oracle).invert();
	}

	@Override
	public PcodeStability<V> assign(
			Identifier id,
			ValueExpression expression,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (isBottom()) {
			return bottom();
		}

		V post = aux.assign(id, expression, pp, oracle);
		if (post.isBottom()) {
			return bottom();
		}

		if (!trends.lattice.canProcess(id, pp, oracle) ||
			!trends.lattice.canProcess(expression, pp, oracle)) {
			return new PcodeStability<>(post, trends);
		}

		if (!trends.knowsIdentifier(id)) {
			return new PcodeStability<>(post, trends.putState(id, Trend.STABLE));
		}

		Trend t = Trend.TOP;

		t = increasingIfLess(id, expression, pp, oracle);
		if (expression instanceof UnaryExpression ue) {
			if (ue.getOperator() instanceof PcodeUnaryOperator op) {
				int opcode = op.getOp().getOpcode();
				if (opcode == PcodeOp.INT_NEGATE || opcode == PcodeOp.INT_2COMP ||
					opcode == PcodeOp.FLOAT_NEG) {
					t = increasingIfLess(id, expression, pp, oracle);
				}
			}
		}
		else if (expression instanceof BinaryExpression be) {
			if (be.getOperator() instanceof PcodeBinaryOperator op) {
				int opcode = op.getOp().getOpcode();
				SymbolicExpression left = be.getLeft();
				SymbolicExpression right = be.getRight();

				boolean isLeft = id.equals(left);
				boolean isRight = id.equals(right);

				// x = a / 0
				if ((opcode == PcodeOp.INT_DIV || opcode == PcodeOp.FLOAT_DIV) && query(
					binary(ComparisonEq.INSTANCE, right, constantInt(0, pp), pp), pp, oracle)) {
					return bottom();
				}

				if (isLeft || isRight) {
					SymbolicExpression other = isLeft ? right : left;
					if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.FLOAT_ADD) {
						// x = x + other || x = other + x
						t = increasingIfGreater(other, constantInt(0, pp), pp, oracle);
					}
					else if (opcode == PcodeOp.INT_SUB || opcode == PcodeOp.FLOAT_SUB) {
						// x = x - other
						if (isLeft) {
							t = increasingIfLess(other, constantInt(0, pp), pp, oracle);
						}
					}
					else if (opcode == PcodeOp.INT_MULT || opcode == PcodeOp.FLOAT_MULT) {
						// x = x * other || x = other * x
						if (query(binary(ComparisonEq.INSTANCE, id, constantInt(0, pp), pp), pp,
							oracle) ||
							query(binary(ComparisonEq.INSTANCE, other, constantInt(1, pp), pp), pp,
								oracle)) {
							// id == 0 || other == 1
							t = Trend.STABLE;
						}
						else if (query(binary(ComparisonGt.INSTANCE, id, constantInt(0, pp), pp),
							pp, oracle)) {
							// id > 0
							t = increasingIfGreater(other, constantInt(1, pp), pp, oracle);
						}
						else if (query(binary(ComparisonLt.INSTANCE, id, constantInt(0, pp), pp),
							pp, oracle)) {
							// id < 0
							t = increasingIfLess(other, constantInt(1, pp), pp, oracle);
						}
						else if (query(binary(ComparisonGe.INSTANCE, id, constantInt(0, pp), pp),
							pp, oracle)) {
							// id >= 0
							t = nonDecreasingIfGreater(other, constantInt(1, pp), pp, oracle);
						}
						else if (query(binary(ComparisonLe.INSTANCE, id, constantInt(0, pp), pp),
							pp, oracle)) {
							// id <= 0
							t = nonDecreasingIfLess(other, constantInt(1, pp), pp, oracle);
						}
						else if (query(binary(ComparisonNe.INSTANCE, id, constantInt(0, pp), pp),
							pp, oracle) &&
							query(binary(ComparisonNe.INSTANCE, other, constantInt(1, pp), pp), pp,
								oracle)) {
							// id != 0 && other != 1
							t = Trend.NON_STABLE;
						}
					}
					else if (opcode == PcodeOp.INT_DIV || opcode == PcodeOp.FLOAT_DIV) {
						// x = x / other
						if (isLeft) {
							if (query(binary(ComparisonEq.INSTANCE, id, constantInt(0, pp), pp), pp,
								oracle) ||
								query(binary(ComparisonEq.INSTANCE, other, constantInt(1, pp), pp),
									pp, oracle)) {
								// id == 0 || other == 1
								t = Trend.STABLE;
							}
							else if (query(
								binary(ComparisonGt.INSTANCE, id, constantInt(0, pp), pp), pp,
								oracle)) {
								// id > 0
								t = increasingIfBetweenZeroAndOne(other, pp, oracle);
							}
							else if (query(
								binary(ComparisonLt.INSTANCE, id, constantInt(0, pp), pp), pp,
								oracle)) {
								// id < 0
								t = increasingIfOutsideZeroAndOne(other, pp, oracle);
							}
							else if (query(
								binary(ComparisonGe.INSTANCE, id, constantInt(0, pp), pp), pp,
								oracle)) {
								// id >= 0
								t = nonDecreasingIfBetweenZeroAndOne(other, pp, oracle);
							}
							else if (query(
								binary(ComparisonLe.INSTANCE, id, constantInt(0, pp), pp), pp,
								oracle)) {
								// id <= 0
								t = nonDecreasingIfOutsideZeroAndOne(other, pp, oracle);
							}
							else if (query(
								binary(ComparisonNe.INSTANCE, id, constantInt(0, pp), pp), pp,
								oracle) &&
								query(binary(ComparisonNe.INSTANCE, other, constantInt(1, pp), pp),
									pp, oracle)) {
								// id != 0 && other != 1
								t = Trend.NON_STABLE;
							}
						}
					}
				}
			}
		}

		ValueEnvironment<Trend> trnd = stabilize(trends).putState(id, t);
		if (trnd.isBottom()) {
			return bottom();
		}
		return new PcodeStability<>(post, trnd);
	}

	@Override
	public PcodeStability<V> smallStepSemantics(
			ValueExpression expression,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		V post = aux.smallStepSemantics(expression, pp, oracle);
		ValueEnvironment<Trend> sss = stabilize(trends).smallStepSemantics(expression, pp, oracle);
		if (post.isBottom() || sss.isBottom()) {
			return bottom();
		}
		return new PcodeStability<>(post, sss);
	}

	@Override
	public PcodeStability<V> assume(
			ValueExpression expression,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {
		V post = aux.assume(expression, src, dest, oracle);
		ValueEnvironment<Trend> assume = trends.assume(expression, src, dest, oracle);
		if (post.isBottom() || assume.isBottom()) {
			return bottom();
		}
		return new PcodeStability<>(post, assume);
	}

	@Override
	public boolean knowsIdentifier(
			Identifier id) {
		return aux.knowsIdentifier(id) || trends.knowsIdentifier(id);
	}

	@Override
	public PcodeStability<V> forgetIdentifier(
			Identifier id)
			throws SemanticException {
		return new PcodeStability<>(aux.forgetIdentifier(id), trends.forgetIdentifier(id));
	}

	@Override
	public PcodeStability<V> forgetIdentifiersIf(
			Predicate<Identifier> test)
			throws SemanticException {
		return new PcodeStability<>(aux.forgetIdentifiersIf(test),
			trends.forgetIdentifiersIf(test));
	}

	@Override
	public Satisfiability satisfies(
			ValueExpression expression,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return aux.satisfies(expression, pp, oracle);
	}

	@Override
	public StructuredRepresentation representation() {
		return new ObjectRepresentation(Map.of(
			"aux", aux.representation(),
			"trends", trends.representation()));
	}

	@Override
	public boolean equals(
			Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PcodeStability<?> other = (PcodeStability<?>) obj;
		return Objects.equals(aux, other.aux) && Objects.equals(trends, other.trends);
	}

	@Override
	public int hashCode() {
		return Objects.hash(aux, trends);
	}

	@Override
	public String toString() {
		return representation().toString();
	}

	/**
	 * Yields the per-variable trends contained in this domain instance.
	 * 
	 * @return the trends
	 */
	public ValueEnvironment<Trend> getTrends() {
		return trends;
	}

	/**
	 * Yields the auxiliary domain contained in this domain instance.
	 * 
	 * @return the auxiliary domain
	 */
	public V getAuxiliaryDomain() {
		return aux;
	}

	/**
	 * Yields the combination of the trends in this stability instance with the
	 * ones contained in the given one. This operation is to be interpreted as
	 * the sequential concatenation of the two: if two (blocks of) instructions
	 * are executed sequentially, a variable having {@code t1} trend in the
	 * former and {@code t2} trend in the latter would have
	 * {@code t1.combine(t2)} as an overall trend. This delegates to
	 * {@link Trend#combine(Trend)} for single-trend combination.
	 * 
	 * @param other the other trends
	 * 
	 * @return the combination of the two trends
	 * 
	 * @throws SemanticException if something goes wrong during the computation
	 */
	public PcodeStability<V> combine(
			PcodeStability<V> other)
			throws SemanticException {
		ValueEnvironment<Trend> result =
			new ValueEnvironment<>(other.trends.lattice, other.trends.function);

		for (Identifier id : other.trends.getKeys()) {
			// we iterate only on the keys of post to remove the ones that went
			// out of scope
			if (trends.knowsIdentifier(id)) {
				Trend tmp = trends.getState(id).combine(other.trends.getState(id));
				result = result.putState(id, tmp);
			}
		}

		return new PcodeStability<>(other.aux, result);
	}

	/**
	 * Yields a mapping from {@link Trend}s to the {@link Identifier}s having
	 * that trend.
	 * 
	 * @return the mapping
	 */
	public Map<Trend, Set<Identifier>> getCovarianceClasses() {
		Map<Trend, Set<Identifier>> map = new HashMap<>();

		for (Identifier id : trends.getKeys()) {
			Trend t = trends.getState(id);
			map.computeIfAbsent(t, k -> new HashSet<>()).add(id);
		}

		return map;
	}

	private static ValueEnvironment<Trend> stabilize(
			ValueEnvironment<Trend> trends) {
		ValueEnvironment<Trend> result = new ValueEnvironment<>(trends.lattice);

		for (Identifier id : trends.getKeys()) {
			result = result.putState(id, Trend.STABLE);
		}

		return result;
	}
}
