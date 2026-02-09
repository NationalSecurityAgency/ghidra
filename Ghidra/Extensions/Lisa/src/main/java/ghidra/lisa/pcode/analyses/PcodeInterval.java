/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.math.BigInteger;
import java.util.Objects;

import generic.stl.Pair;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.Satisfiability;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalValueDomain;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.symbolic.value.operator.binary.*;
import it.unive.lisa.symbolic.value.operator.unary.UnaryOperator;
import it.unive.lisa.type.Untyped;
import it.unive.lisa.util.numeric.IntInterval;
import it.unive.lisa.util.numeric.MathNumber;
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * The overflow-insensitive interval abstract domain, approximating integer
 * values as the minimum numeric interval containing them. It is implemented as
 * a {@link BaseNonRelationalValueDomain}, handling top and bottom values for
 * the expression evaluation and bottom values for the expression
 * satisfiability. Top and bottom cases for least upper bounds, widening and
 * less or equals operations are handled by {@link BaseLattice} in
 * {@link BaseLattice#lub}, {@link BaseLattice#widening} and
 * {@link BaseLattice#lessOrEqual} methods, respectively.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:vincenzo.arceri@unive.it">Vincenzo Arceri</a>
 */
public class PcodeInterval
		implements PcodeNonRelationalValueDomain<PcodeInterval>, Comparable<PcodeInterval> {

	/**
	 * The abstract zero ({@code [0, 0]}) element.
	 */
	public static final PcodeInterval ZERO = new PcodeInterval(LongInterval.ZERO);

	/**
	 * The abstract true ({@code [1, 1]}) element.
	 */
	public static final PcodeInterval ONE = new PcodeInterval(LongInterval.ONE);

	/**
	 * The abstract top ({@code [-Inf, +Inf]}) element.
	 */
	public static final PcodeInterval TOP = new PcodeInterval(LongInterval.INFINITY);

	/**
	 * The abstract bottom element.
	 */
	public static final PcodeInterval BOTTOM = new PcodeInterval(null);

	/**
	 * The interval represented by this domain element.
	 */
	public final LongInterval interval;

	public PcodeOp target;
	public MathNumber bound;
	public LongInterval intEq;
	public LongInterval intNeq;
	public boolean rightIsExpr;

	/**
	 * Builds the interval.
	 * 
	 * @param interval the underlying {@link LongInterval}
	 */
	public PcodeInterval(
			LongInterval interval) {
		this.interval = interval;
	}

	/**
	 * Builds the interval.
	 * 
	 * @param low  the lower bound
	 * @param high the higher bound
	 */
	public PcodeInterval(
			MathNumber low,
			MathNumber high) {
		this(new LongInterval(low, high));
	}

	/**
	 * Builds the top interval.
	 */
	public PcodeInterval() {
		this(LongInterval.INFINITY);
	}

	@Override
	public PcodeInterval top() {
		return TOP;
	}

	@Override
	public boolean isTop() {
		return interval != null && interval.isInfinity();
	}

	@Override
	public PcodeInterval bottom() {
		return BOTTOM;
	}

	@Override
	public boolean isBottom() {
		return interval == null;
	}

	@Override
	public StructuredRepresentation representation() {
		if (isBottom()) {
			return Lattice.bottomRepresentation();
		}

		return new StringRepresentation(interval.toString());
	}

	@Override
	public String toString() {
		return representation().toString();
	}

	@Override
	public PcodeInterval evalIdentifier(
			Identifier id,
			ValueEnvironment<PcodeInterval> environment,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (id.getCodeLocation() instanceof PcodeLocation ploc) {
			Varnode vn = id2vn(id);
			if (vn != null && vn.isConstant()) {
				return evalNonNullConstant(new Constant(Untyped.INSTANCE, vn.getOffset(), ploc), pp,
					oracle);
			}
		}
		return environment.getState(id);
	}

	private Varnode id2vn(Identifier id) {
		String name = id.getName();
		PcodeLocation loc = (PcodeLocation) id.getCodeLocation();
		Varnode output = loc.op.getOutput();
		if (output != null) {
			if (name.equals(output.getAddress().toString())) {
				return output;
			}
		}
		for (Varnode vn : loc.op.getInputs()) {
			if (name.equals(vn.getAddress().toString())) {
				return vn;
			}
		}
		return null;
	}

	@Override
	public PcodeInterval evalNonNullConstant(
			Constant constant,
			ProgramPoint pp,
			SemanticOracle oracle) {

		Object cval = constant.getValue();
		if (cval instanceof Long lval) {
			return new PcodeInterval(new MathNumber(lval), new MathNumber(lval));
		}
		if (cval instanceof Integer ival) {
			return new PcodeInterval(new MathNumber(ival), new MathNumber(ival));
		}
		if (cval instanceof Short sval) {
			return new PcodeInterval(new MathNumber(sval), new MathNumber(sval));
		}
		if (cval instanceof Byte bval) {
			return new PcodeInterval(new MathNumber(bval), new MathNumber(bval));
		}
		if (cval instanceof Boolean bval) {
			return new PcodeInterval(new MathNumber(bval ? 1L : 0L),
				new MathNumber(bval ? 1L : 0L));
		}
		Msg.error(this, "Unknown type for constant: " + cval);

		return top();
	}

	@Override
	public PcodeInterval evalUnaryExpression(
			UnaryOperator operator,
			PcodeInterval arg,
			ProgramPoint pp,
			SemanticOracle oracle) {
		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		int opcode = op.getOpcode();
		PcodeInterval result = arg;
		if (opcode == PcodeOp.INT_NEGATE || opcode == PcodeOp.INT_2COMP ||
			opcode == PcodeOp.FLOAT_NEG) {
			result = arg.isTop() ? top()
					: new PcodeInterval(arg.interval.mul(LongInterval.MINUS_ONE));
		}
		if (opcode == PcodeOp.BOOL_NEGATE) {
			result = arg.isTop() ? top()
					: new PcodeInterval(arg.interval.complement());
			result.target = ploc.op;
		}
		return result;
	}

	/**
	 * Tests whether this interval instance corresponds (i.e., concretizes)
	 * exactly to the given integer. The tests is performed through
	 * {@link IntInterval#is(int)}.
	 * 
	 * @param n the integer value
	 * 
	 * @return {@code true} if that condition holds
	 */
	public boolean is(
			int n) {
		return !isBottom() && interval.is(n);
	}

	@Override
	public PcodeInterval evalBinaryExpression(
			BinaryOperator operator,
			PcodeInterval left,
			PcodeInterval right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		if (!(pp.getLocation() instanceof PcodeLocation ploc)) {
			return top();
		}
		Pair<PcodeInterval, PcodeInterval> pair = new Pair<>(left, right);

		if (operator instanceof PcodeBinaryOperator) {
			return evalPcodeBinaryExpression(pair, ploc.op);
		}

		try {
			LongInterval interval1 = pair.first.interval;
			LongInterval interval2 = pair.second.interval;
			boolean exprOnRight = interval2.isFinite();
			if (exprOnRight && interval1.isFinite()) {
				exprOnRight = interval2.getLow().equals(interval2.getHigh());
			}
			PcodeInterval result = evalBooleanBinaryExpression(pair, operator);

			result.target = ploc.op;
			if (!(operator instanceof LogicalOperation)) {
				Pair<PcodeInterval, PcodeInterval> basePair =
					new Pair<>(exprOnRight ? top() : left, exprOnRight ? right : top());
				PcodeInterval init = exprOnRight ? left : right;
				PcodeInterval bounds = exprOnRight ? right : left;
				PcodeInterval baseResult = evalBooleanBinaryExpression(basePair, operator);
				PcodeInterval eq = baseResult.narrowing(init);
				PcodeInterval neq = baseResult.complement().narrowing(init);
				result.bound = bounds.interval.isFinite() ? bounds.interval.getLow() : null;
				result.rightIsExpr = exprOnRight;
				result.intEq = eq.interval;
				result.intNeq = neq.interval;
			}
			return result;
		}
		catch (SemanticException e) {
			Msg.error(this, e.getMessage());
		}

		return top();
	}

	protected PcodeInterval evalPcodeBinaryExpression(Pair<PcodeInterval, PcodeInterval> pair,
			PcodeOp op) {

		PcodeInterval left = pair.first;
		PcodeInterval right = pair.second;
		int opcode = op.getOpcode();
		if (!(opcode == PcodeOp.INT_DIV) && !(opcode == PcodeOp.FLOAT_DIV) &&
			(left.isTop() || right.isTop())) {
			// with div, we can return zero or bottom even if one of the
			// operands is top
			return top();
		}

		return switch (opcode) {
			case PcodeOp.INT_ADD, PcodeOp.FLOAT_ADD -> new PcodeInterval(
				left.interval.plus(right.interval));
			case PcodeOp.INT_SUB, PcodeOp.FLOAT_SUB -> new PcodeInterval(
				left.interval.diff(right.interval));
			case PcodeOp.INT_MULT, PcodeOp.FLOAT_MULT -> {
				if (left.is(0) || right.is(0)) {
					yield ZERO;
				}
				yield new PcodeInterval(left.interval.mul(right.interval));
			}
			case PcodeOp.INT_DIV, PcodeOp.FLOAT_DIV -> {
				if (left.isTop() || right.isTop()) {
					yield top();
				}
				if (right.is(0)) {
					yield bottom();
				}
				if (left.is(0)) {
					yield ZERO;
				}
				yield new PcodeInterval(left.interval.div(right.interval, false, false));
			}
			case PcodeOp.INT_REM, PcodeOp.INT_SREM -> {
				if (right.is(0)) {
					yield bottom();
				}
				if (left.is(0)) {
					yield ZERO;
				}
				if (left.isTop() || right.isTop()) {
					yield top();
				}
				// the result takes the sign of the dividend - l%r is:
				// - [-M+1,0] if l.high < 0 (fully negative)
				// - [0,M-1] if l.low > 0 (fully positive)
				// - [-M+1,M-1] otherwise
				// where M is
				// - -r.low if r.high < 0 (fully negative)
				// - r.high if r.low > 0 (fully positive)
				// - max(abs(r.low),abs(r.right)) otherwise
				MathNumber M;
				if (right.interval.getHigh().compareTo(MathNumber.ZERO) < 0) {
					M = right.interval.getLow().multiply(MathNumber.MINUS_ONE);
				}
				else if (right.interval.getLow().compareTo(MathNumber.ZERO) > 0) {
					M = right.interval.getHigh();
				}
				else {
					M = right.interval.getLow().abs().max(right.interval.getHigh().abs());
				}

				if (left.interval.getHigh().compareTo(MathNumber.ZERO) < 0) {
					yield new PcodeInterval(M.multiply(MathNumber.MINUS_ONE).add(MathNumber.ONE),
						MathNumber.ZERO);
				}
				if (left.interval.getLow().compareTo(MathNumber.ZERO) > 0) {
					yield new PcodeInterval(MathNumber.ZERO, M.subtract(MathNumber.ONE));
				}
				yield new PcodeInterval(M.multiply(MathNumber.MINUS_ONE).add(MathNumber.ONE),
					M.subtract(MathNumber.ONE));
			}
			default -> left;
		};
	}

	protected PcodeInterval evalBooleanBinaryExpression(Pair<PcodeInterval, PcodeInterval> pair,
			BinaryOperator operator) throws SemanticException {
		boolean exprOnRight = pair.second.interval.isFinite();

		PcodeInterval starting = exprOnRight ? pair.first : pair.second;
		PcodeInterval eval = exprOnRight ? pair.second : pair.first;
		LongInterval lval = eval.interval;

		boolean lowIsMinusInfinity = lval.lowIsMinusInfinity();
		PcodeInterval low_inf = new PcodeInterval(lval.getLow(), MathNumber.PLUS_INFINITY);
		PcodeInterval lowp1_inf =
			new PcodeInterval(lval.getLow().add(MathNumber.ONE), MathNumber.PLUS_INFINITY);
		PcodeInterval inf_high = new PcodeInterval(MathNumber.MINUS_INFINITY, lval.getHigh());
		PcodeInterval inf_highm1 =
			new PcodeInterval(MathNumber.MINUS_INFINITY, lval.getHigh().subtract(MathNumber.ONE));

		PcodeInterval update = switch (operator) {
			case ComparisonEq op -> new PcodeInterval(lval);
			case ComparisonNe op -> new PcodeInterval(lval.complement());
			case ComparisonLe op -> {
				if (exprOnRight) {
					yield starting.glb(inf_high);
				}
				yield lowIsMinusInfinity ? null : starting.glb(low_inf);
			}
			case ComparisonLt op -> {
				if (exprOnRight) {
					yield lowIsMinusInfinity ? eval : starting.glb(inf_highm1);
				}
				yield lowIsMinusInfinity ? null : starting.glb(lowp1_inf);
			}
			case ComparisonGe op -> {
				if (exprOnRight) {
					yield lowIsMinusInfinity ? null : starting.glb(low_inf);
				}
				yield starting.glb(inf_high);
			}
			case ComparisonGt op -> {
				if (exprOnRight) {
					yield lowIsMinusInfinity ? null : starting.glb(lowp1_inf);
				}
				yield lowIsMinusInfinity ? eval : starting.glb(inf_highm1);
			}
			case LogicalOr op -> {
				MathNumber min = starting.interval.getLow().min(eval.interval.getLow());
				MathNumber max = starting.interval.getHigh().max(eval.interval.getHigh());
				yield new PcodeInterval(min, max);
			}
			default -> throw new AssertionError();
		};

		if (update == null || update.isBottom()) {
			return new PcodeInterval(LongInterval.ZERO);
		}
		return update;
	}

	@Override
	public PcodeInterval lubAux(
			PcodeInterval other)
			throws SemanticException {
		MathNumber newLow = interval.getLow().min(other.interval.getLow());
		MathNumber newHigh = interval.getHigh().max(other.interval.getHigh());
		PcodeInterval res = newLow.isMinusInfinity() && newHigh.isPlusInfinity() ? top()
				: new PcodeInterval(newLow, newHigh);
		res.target = this.target;
		res.bound = this.bound;
		return res;
	}

	@Override
	public PcodeInterval glbAux(
			PcodeInterval other) {
		MathNumber newLow = interval.getLow().max(other.interval.getLow());
		MathNumber newHigh = interval.getHigh().min(other.interval.getHigh());

		if (newLow.compareTo(newHigh) > 0) {
			return bottom();
		}
		return newLow.isMinusInfinity() && newHigh.isPlusInfinity() ? top()
				: new PcodeInterval(newLow, newHigh);
	}

	@Override
	public PcodeInterval wideningAux(
			PcodeInterval other)
			throws SemanticException {
		MathNumber newLow, newHigh;
		if (other.interval.getHigh().compareTo(interval.getHigh()) > 0) {
			newHigh = MathNumber.PLUS_INFINITY;
		}
		else {
			newHigh = interval.getHigh();
		}

		if (other.interval.getLow().compareTo(interval.getLow()) < 0) {
			newLow = MathNumber.MINUS_INFINITY;
		}
		else {
			newLow = interval.getLow();
		}

		return newLow.isMinusInfinity() && newHigh.isPlusInfinity() ? top()
				: new PcodeInterval(newLow, newHigh);
	}

	@Override
	public PcodeInterval narrowingAux(
			PcodeInterval other)
			throws SemanticException {
		MathNumber newLow, newHigh;
		newHigh = interval.getHigh().isInfinite() ? other.interval.getHigh() : interval.getHigh();
		newLow = interval.getLow().isInfinite() ? other.interval.getLow() : interval.getLow();
		return new PcodeInterval(newLow, newHigh);
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeInterval other)
			throws SemanticException {
		return other.interval.includes(interval);
	}

	@Override
	public Satisfiability satisfiesBinaryExpression(
			BinaryOperator operator,
			PcodeInterval left,
			PcodeInterval right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		return Satisfiability.UNKNOWN;
	}

	@Override
	public int hashCode() {
		return Objects.hash(interval);
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
		PcodeInterval other = (PcodeInterval) obj;
		return Objects.equals(this.interval, other.interval);
	}

	@Override
	public ValueEnvironment<PcodeInterval> assumeBinaryExpression(
			ValueEnvironment<PcodeInterval> environment,
			BinaryOperator operator,
			ValueExpression left,
			ValueExpression right,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {

		if (operator instanceof PcodeBinaryOperator) {
			return environment;
		}

		Identifier id = null;
		PcodeInterval eval = null;
		PcodeInterval val = null;
		boolean complement = false;
		if (left instanceof Identifier leftId) {
			id = leftId;
			eval = eval(right, environment, src, oracle);
			val = environment.getState(leftId);
			if (val.isBottom()) {
				return environment.bottom();
			}
			if (operator instanceof ComparisonNe) {
				eval = new PcodeInterval(eval.interval.complement());
				complement = true;
			}
		}
		if (id == null) {
			return environment;
		}

		environment = updateImpliedConditions(environment, src, dest, val, complement);

		return environment.putState(id, eval);
	}

	protected ValueEnvironment<PcodeInterval> updateImpliedConditions(
			ValueEnvironment<PcodeInterval> environment,
			ProgramPoint src, ProgramPoint dest, PcodeInterval val, boolean complement) {
		if (val.target != null && val.bound != null) {
			Varnode tgt = val.rightIsExpr ? val.target.getInput(0) : val.target.getInput(1);
			Identifier vnId =
				new Variable(Untyped.INSTANCE, tgt.getAddress().toString(), dest.getLocation());
			PcodeInterval res = new PcodeInterval(complement ? val.intNeq : val.intEq);
			return environment.putState(vnId, res);
		}
		return environment;
	}

	protected PcodeInterval complement() {
		PcodeInterval comp = new PcodeInterval(this.interval.complement());
		return comp;
	}

	@Override
	public int compareTo(
			PcodeInterval o) {
		if (isBottom()) {
			return o.isBottom() ? 0 : -1;
		}
		if (isTop()) {
			return o.isTop() ? 0 : 1;
		}
		if (o.isBottom()) {
			return 1;
		}
		if (o.isTop()) {
			return -1;
		}
		return interval.compareTo(o.interval);
	}

	@Override
	public PcodeInterval getValue(RegisterValue rv) {
		if (rv != null) {
			BigInteger val = rv.getUnsignedValue();
			if (val != null) {
				return new PcodeInterval(new LongInterval(val.longValue(), val.longValue()));
			}
		}
		return top();
	}

}
