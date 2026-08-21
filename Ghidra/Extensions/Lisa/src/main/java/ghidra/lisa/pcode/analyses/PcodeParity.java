/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.math.BigInteger;

import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalValueDomain;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.symbolic.value.operator.binary.BinaryOperator;
import it.unive.lisa.symbolic.value.operator.binary.ComparisonEq;
import it.unive.lisa.symbolic.value.operator.unary.UnaryOperator;
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * The overflow-insensitive Parity abstract domain, tracking if a numeric value
 * is even or odd, implemented as a {@link BaseNonRelationalValueDomain},
 * handling top and bottom values for the expression evaluation and bottom
 * values for the expression satisfiability. Top and bottom cases for least
 * upper bound, widening and less or equals operations are handled by
 * {@link BaseLattice} in {@link BaseLattice#lub}, {@link BaseLattice#widening}
 * and {@link BaseLattice#lessOrEqual} methods, respectively.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:vincenzo.arceri@unive.it">Vincenzo Arceri</a>
 */
public class PcodeParity implements PcodeNonRelationalValueDomain<PcodeParity> {

	/**
	 * The abstract even element.
	 */
	public static final PcodeParity EVEN = new PcodeParity((byte) 3);

	/**
	 * The abstract odd element.
	 */
	public static final PcodeParity ODD = new PcodeParity((byte) 2);

	/**
	 * The abstract top element.
	 */
	public static final PcodeParity TOP = new PcodeParity((byte) 0);

	/**
	 * The abstract bottom element.
	 */
	public static final PcodeParity BOTTOM = new PcodeParity((byte) 1);

	private final byte parity;

	/**
	 * Builds the parity abstract domain, representing the top of the parity
	 * abstract domain.
	 */
	public PcodeParity() {
		this((byte) 0);
	}

	/**
	 * Builds the parity instance for the given parity value.
	 * 
	 * @param parity the sign (0 = top, 1 = bottom, 2 = odd, 3 = even)
	 */
	public PcodeParity(
			byte parity) {
		this.parity = parity;
	}

	@Override
	public PcodeParity top() {
		return TOP;
	}

	@Override
	public PcodeParity bottom() {
		return BOTTOM;
	}

	@Override
	public StructuredRepresentation representation() {
		if (isBottom()) {
			return Lattice.bottomRepresentation();
		}
		if (isTop()) {
			return Lattice.topRepresentation();
		}

		String repr = this == EVEN ? "Even" : "Odd";

		return new StringRepresentation(repr);
	}

	@Override
	public PcodeParity evalNullConstant(
			ProgramPoint pp,
			SemanticOracle oracle) {
		return top();
	}

	@Override
	public PcodeParity evalNonNullConstant(
			Constant constant,
			ProgramPoint pp,
			SemanticOracle oracle) {

		Object cval = constant.getValue();
		if (cval instanceof Long lval) {
			return lval % 2 == 0 ? EVEN : ODD;
		}
		if (cval instanceof Integer ival) {
			return ival % 2 == 0 ? EVEN : ODD;
		}
		if (cval instanceof Short sval) {
			return sval % 2 == 0 ? EVEN : ODD;
		}
		if (cval instanceof Byte bval) {
			return bval % 2 == 0 ? EVEN : ODD;
		}
		if (cval instanceof Boolean bval) {
			return bval ? ODD : EVEN;
		}
		Msg.error(this, "Unknown type for constant: " + cval);

		return top();
	}

	/**
	 * Yields whether or not this is the even parity.
	 * 
	 * @return {@code true} if that condition holds
	 */
	public boolean isEven() {
		return this == EVEN;
	}

	/**
	 * Yields whether or not this is the odd parity.
	 * 
	 * @return {@code true} if that condition holds
	 */
	public boolean isOdd() {
		return this == ODD;
	}

	@Override
	public PcodeParity evalUnaryExpression(
			UnaryOperator operator,
			PcodeParity arg,
			ProgramPoint pp,
			SemanticOracle oracle) {
		return arg;
	}

	@Override
	public PcodeParity evalBinaryExpression(
			BinaryOperator operator,
			PcodeParity left,
			PcodeParity right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		if (left.isTop() || right.isTop()) {
			return top();
		}

		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		int opcode = op.getOpcode();
		if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.FLOAT_ADD ||
			opcode == PcodeOp.INT_SUB || opcode == PcodeOp.FLOAT_SUB) {
			return (right.equals(left)) ? EVEN : ODD;
		}
		else if (opcode == PcodeOp.INT_AND || opcode == PcodeOp.BOOL_AND) {
			return (right.equals(left)) ? left : EVEN;
		}
		else if (opcode == PcodeOp.INT_OR || opcode == PcodeOp.BOOL_OR) {
			return (right.equals(left)) ? left : ODD;
		}
		else if (opcode == PcodeOp.INT_XOR || opcode == PcodeOp.BOOL_XOR) {
			return (right.equals(left)) ? EVEN : ODD;
		}
		else if (opcode == PcodeOp.INT_MULT || opcode == PcodeOp.FLOAT_MULT) {
			return left.isEven() || right.isEven() ? EVEN : ODD;
		}
		else if (opcode == PcodeOp.INT_DIV || opcode == PcodeOp.FLOAT_DIV) {
			if (left.isOdd()) {
				return right.isOdd() ? ODD : EVEN;
			}
			return right.isOdd() ? EVEN : TOP;
		}
		else if (opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM) {
			return TOP;
		}
		else if (opcode == PcodeOp.INT_AND) {
			if (left.equals(EVEN) || right.equals(EVEN)) {
				return EVEN;
			}
			return ODD;
		}
		else if (opcode == PcodeOp.INT_OR) {
			if (left.equals(ODD) || right.equals(ODD)) {
				return ODD;
			}
			return EVEN;
		}
		else if (opcode == PcodeOp.INT_XOR) {
			if (left.equals(right))
				return EVEN;
			return ODD;
		}
		return left;
	}

	@Override
	public PcodeParity lubAux(
			PcodeParity other)
			throws SemanticException {
		return TOP;
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeParity other)
			throws SemanticException {
		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + parity;
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
		PcodeParity other = (PcodeParity) obj;
		if (parity != other.parity) {
			return false;
		}
		return true;
	}

	@Override
	public ValueEnvironment<PcodeParity> assumeBinaryExpression(
			ValueEnvironment<PcodeParity> environment,
			BinaryOperator operator,
			ValueExpression left,
			ValueExpression right,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {
		if (operator instanceof ComparisonEq) {
			if (left instanceof Identifier) {
				PcodeParity eval = eval(right, environment, src, oracle);
				if (eval.isBottom()) {
					return environment.bottom();
				}
				return environment.putState((Identifier) left, eval);
			}
			else if (right instanceof Identifier) {
				PcodeParity eval = eval(left, environment, src, oracle);
				if (eval.isBottom()) {
					return environment.bottom();
				}
				return environment.putState((Identifier) right, eval);
			}
		}
		return environment;
	}

	@Override
	public PcodeParity getValue(RegisterValue rv) {
		if (rv != null) {
			BigInteger val = rv.getUnsignedValue();
			if (val != null) {
				return new PcodeParity((byte) (val.longValue() % 2 == 0 ? 3 : 2));
			}
		}
		return top();
	}

}
