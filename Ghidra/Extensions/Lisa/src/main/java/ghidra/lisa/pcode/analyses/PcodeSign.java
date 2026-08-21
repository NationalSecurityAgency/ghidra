/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.math.BigInteger;

import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.Satisfiability;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalValueDomain;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.symbolic.value.operator.binary.*;
import it.unive.lisa.symbolic.value.operator.ternary.TernaryOperator;
import it.unive.lisa.symbolic.value.operator.unary.UnaryOperator;
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * The basic overflow-insensitive Sign abstract domain, tracking zero, strictly
 * positive and strictly negative integer values, implemented as a
 * {@link BaseNonRelationalValueDomain}, handling top and bottom values for the
 * expression evaluation and bottom values for the expression satisfiability.
 * Top and bottom cases for least upper bounds, widening and less or equals
 * operations are handled by {@link BaseLattice} in {@link BaseLattice#lub},
 * {@link BaseLattice#widening} and {@link BaseLattice#lessOrEqual} methods,
 * respectively.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:vincenzo.arceri@unive.it">Vincenzo Arceri</a>
 */
public class PcodeSign implements PcodeNonRelationalValueDomain<PcodeSign> {

	public static final PcodeSign POS = new PcodeSign((byte) 4);
	public static final PcodeSign NEG = new PcodeSign((byte) 3);
	public static final PcodeSign ZERO = new PcodeSign((byte) 2);

	public static final PcodeSign TOP = new PcodeSign((byte) 0);
	public static final PcodeSign BOTTOM = new PcodeSign((byte) 1);

	private final byte sign;

	/**
	 * Builds the sign abstract domain, representing the top of the sign
	 * abstract domain.
	 */
	public PcodeSign() {
		this((byte) 0);
	}

	/**
	 * Builds the sign instance for the given sign value.
	 * 
	 * @param sign the sign (0 = top, 1 = bottom, 2 = zero, 3 = negative, 4 =
	 *                 positive)
	 */
	public PcodeSign(byte sign) {
		this.sign = sign;
	}

	@Override
	public PcodeSign evalNullConstant(
			ProgramPoint pp,
			SemanticOracle oracle) {
		return top();
	}

	@Override
	public PcodeSign evalNonNullConstant(
			Constant constant,
			ProgramPoint pp,
			SemanticOracle oracle) {

		Object cval = constant.getValue();
		if (cval instanceof Long lval) {
			return lval == 0 ? ZERO : lval > 0 ? POS : NEG;
		}
		if (cval instanceof Integer ival) {
			return ival == 0 ? ZERO : ival > 0 ? POS : NEG;
		}
		if (cval instanceof Short sval) {
			return sval == 0 ? ZERO : sval > 0 ? POS : NEG;
		}
		if (cval instanceof Byte bval) {
			return bval == 0 ? ZERO : bval > 0 ? POS : NEG;
		}
		if (cval instanceof Boolean bval) {
			return bval ? POS : ZERO;
		}
		Msg.error(this, "Unknown type for constant: " + cval);

		return top();
	}

	/**
	 * Yields whether or not this is the positive sign.
	 * 
	 * @return {@code true} if that condition holds
	 */
	public boolean isPositive() {
		return this == POS;
	}

	/**
	 * Yields whether or not this is the zero sign.
	 * 
	 * @return {@code true} if that condition holds
	 */
	public boolean isZero() {
		return this == ZERO;
	}

	/**
	 * Yields whether or not this is the negative sign.
	 * 
	 * @return {@code true} if that condition holds
	 */
	public boolean isNegative() {
		return this == NEG;
	}

	/**
	 * Yields the sign opposite to this one. Top and bottom elements do not
	 * change.
	 * 
	 * @return the opposite sign
	 */
	public PcodeSign opposite() {
		if (isTop() || isBottom()) {
			return this;
		}
		return isPositive() ? NEG : isNegative() ? POS : ZERO;
	}

	@Override
	public PcodeSign evalUnaryExpression(
			UnaryOperator operator,
			PcodeSign arg,
			ProgramPoint pp,
			SemanticOracle oracle) {
		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		int opcode = op.getOpcode();

		if (opcode == PcodeOp.INT_NEGATE || opcode == PcodeOp.INT_2COMP ||
			opcode == PcodeOp.FLOAT_NEG) {
			if (arg.isPositive()) {
				return NEG;
			}
			else if (arg.isNegative()) {
				return POS;
			}
			else if (arg.isZero()) {
				return ZERO;
			}
		}
		if (opcode == PcodeOp.FLOAT_ABS) {
			return POS;
		}
		return arg;
	}

	@Override
	public PcodeSign evalBinaryExpression(
			BinaryOperator operator,
			PcodeSign left,
			PcodeSign right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		int opcode = op.getOpcode();

		if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.FLOAT_ADD) {
			if (left.isZero()) {
				return right;
			}
			else if (right.isZero()) {
				return left;
			}
			else if (left.equals(right)) {
				return left;
			}
			return top();
		}
		if (opcode == PcodeOp.INT_SUB || opcode == PcodeOp.FLOAT_SUB ||
			opcode == PcodeOp.INT_XOR) {
			if (left.isZero()) {
				return right.opposite();
			}
			else if (right.isZero()) {
				return left;
			}
			else if (left.equals(right)) {
				return top();
			}
			return left;
		}
		else if (opcode == PcodeOp.INT_SDIV || opcode == PcodeOp.FLOAT_DIV) {
			if (right.isZero()) {
				return bottom();
			}
			else if (left.isZero()) {
				return ZERO;
			}
			else if (left.equals(right)) {
				// top/top = top
				// +/+ = +
				// -/- = +
				return left.isTop() ? left : POS;
			}
			else if (!left.isTop() && left.equals(right.opposite())) {
				// +/- = -
				// -/+ = -
				return NEG;
			}
			else {
				return top();
			}
		}
		else if (opcode == PcodeOp.INT_MULT || opcode == PcodeOp.FLOAT_MULT) {
			if (left.isZero() || right.isZero()) {
				return ZERO;
			}
			else if (left.equals(right)) {
				return POS;
			}
			else {
				return NEG;
			}
		}
		else if (opcode == PcodeOp.INT_AND) {
			if (left.isZero() || right.isZero()) {
				return ZERO;
			}
			else if (left.equals(POS) || right.equals(POS)) {
				return POS;
			}
			else {
				return NEG;
			}
		}
		else if (opcode == PcodeOp.INT_OR) {
			if (left.isZero() && right.isZero()) {
				return ZERO;
			}
			else if (left.equals(NEG) || right.equals(NEG)) {
				return NEG;
			}
			else {
				return POS;
			}
		}
		else if (opcode == PcodeOp.INT_XOR) {
			if (left.equals(right)) {
				return POS;
			}
			return NEG;
		}
		else {
			return left;
		}
	}

	@Override
	public PcodeSign lubAux(
			PcodeSign other)
			throws SemanticException {
		return TOP;
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeSign other)
			throws SemanticException {
		return false;
	}

	@Override
	public PcodeSign top() {
		return TOP;
	}

	@Override
	public PcodeSign bottom() {
		return BOTTOM;
	}

	@Override
	public String toString() {
		return representation().toString();
	}

	@Override
	public StructuredRepresentation representation() {
		if (isBottom()) {
			return Lattice.bottomRepresentation();
		}
		if (isTop()) {
			return Lattice.topRepresentation();
		}

		String repr;
		if (this == ZERO) {
			repr = "0";
		}
		else if (this == POS) {
			repr = "+";
		}
		else {
			repr = "-";
		}

		return new StringRepresentation(repr);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + sign;
		return result;
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
		PcodeSign other = (PcodeSign) obj;
		if (sign != other.sign) {
			return false;
		}
		return true;
	}

	@Override
	public Satisfiability satisfiesBinaryExpression(
			BinaryOperator operator,
			PcodeSign left,
			PcodeSign right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		if (left.isTop() || right.isTop()) {
			return Satisfiability.UNKNOWN;
		}

		if (operator instanceof ComparisonEq) {
			return left.eq(right);
		}
		// e1 <= e2 same as !(e1 > e2)
		if (operator instanceof ComparisonLe) {
			return left.gt(right).negate();
		}
		// e1 < e2 -> !(e1 >= e2) && !(e1 == e2)
		if (operator instanceof ComparisonLt) {
			return left.gt(right)
					.negate()
					.and(left.eq(right).negate());
		}
		if (operator instanceof ComparisonNe) {
			return left.eq(right).negate();
		}

		return Satisfiability.UNKNOWN;
	}

	/**
	 * Tests if this instance is equal to the given one, returning a
	 * {@link Satisfiability} element.
	 * 
	 * @param other the instance
	 * 
	 * @return the satisfiability of {@code this = other}
	 */
	public Satisfiability eq(
			PcodeSign other) {
		if (!this.equals(other)) {
			return Satisfiability.NOT_SATISFIED;
		}
		else if (isZero()) {
			return Satisfiability.SATISFIED;
		}
		else {
			return Satisfiability.UNKNOWN;
		}
	}

	/**
	 * Tests if this instance is greater than the given one, returning a
	 * {@link Satisfiability} element.
	 * 
	 * @param other the instance
	 * 
	 * @return the satisfiability of {@code this > other}
	 */
	public Satisfiability gt(
			PcodeSign other) {
		if (this.equals(other)) {
			return this.isZero() ? Satisfiability.NOT_SATISFIED : Satisfiability.UNKNOWN;
		}
		else if (this.isZero()) {
			return other.isPositive() ? Satisfiability.NOT_SATISFIED : Satisfiability.SATISFIED;
		}
		else if (this.isPositive()) {
			return Satisfiability.SATISFIED;
		}
		else {
			return Satisfiability.NOT_SATISFIED;
		}
	}

	@Override
	public Satisfiability satisfiesTernaryExpression(
			TernaryOperator operator,
			PcodeSign left,
			PcodeSign middle,
			PcodeSign right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		return Satisfiability.UNKNOWN;
	}

	@Override
	public ValueEnvironment<PcodeSign> assumeBinaryExpression(
			ValueEnvironment<PcodeSign> environment,
			BinaryOperator operator,
			ValueExpression left,
			ValueExpression right,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {
		Identifier id;
		PcodeSign eval;
		boolean rightIsExpr;
		if (left instanceof Identifier) {
			eval = eval(right, environment, src, oracle);
			id = (Identifier) left;
			rightIsExpr = true;
		}
		else if (right instanceof Identifier) {
			eval = eval(left, environment, src, oracle);
			id = (Identifier) right;
			rightIsExpr = false;
		}
		else {
			return environment;
		}

		PcodeSign starting = environment.getState(id);
		if (eval.isBottom() || starting.isBottom()) {
			return environment.bottom();
		}

		PcodeSign update = null;
		if (!(operator instanceof PcodeBinaryOperator)) {
			if (operator instanceof ComparisonEq) {
				update = eval;
			}
			else if (operator instanceof ComparisonLe) {
				if (rightIsExpr && eval.isNegative()) {
					update = eval;
				}
				else if (!rightIsExpr && eval.isPositive()) {
					update = eval;
				}
			}
			else if (operator instanceof ComparisonLt) {
				if (rightIsExpr && (eval.isNegative() || eval.isZero())) {
					// x < 0/-
					update = NEG;
				}
				else if (!rightIsExpr && (eval.isPositive() || eval.isZero())) {
					// 0/+ < x
					update = POS;
				}
			}
		}

		if (update == null) {
			return environment;
		}
		else if (update.isBottom()) {
			return environment.bottom();
		}
		else {
			return environment.putState(id, update);
		}
	}

	@Override
	public PcodeSign getValue(RegisterValue rv) {
		if (rv != null) {
			BigInteger val = rv.getUnsignedValue();
			if (val != null) {
				if (val.longValue() == 0L) {
					return new PcodeSign();
				}
				return new PcodeSign((byte) (val.longValue() > 0 ? 1 : -1));
			}
		}
		return top();
	}
}
