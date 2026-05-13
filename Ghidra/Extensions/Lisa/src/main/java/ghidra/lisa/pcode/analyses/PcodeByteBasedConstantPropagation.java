/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.math.BigInteger;
import java.util.Objects;

import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.opbehavior.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Language;
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
import it.unive.lisa.symbolic.value.operator.unary.UnaryOperator;
import it.unive.lisa.type.NumericType;
import it.unive.lisa.type.Type;
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * The overflow-insensitive basic numeric constant propagation abstract domain,
 * tracking if a certain numeric value has constant value or not, implemented as
 * a {@link BaseNonRelationalValueDomain}, handling top and bottom values for
 * the expression evaluation and bottom values for the expression
 * satisfiability. Top and bottom cases for least upper bounds, widening and
 * less or equals operations are handled by {@link BaseLattice} in
 * {@link BaseLattice#lub}, {@link BaseLattice#widening} and
 * {@link BaseLattice#lessOrEqual}, respectively.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:vincenzo.arceri@unive.it">Vincenzo Arceri</a>
 */
public class PcodeByteBasedConstantPropagation
		implements PcodeNonRelationalValueDomain<PcodeByteBasedConstantPropagation> {

	private static final PcodeByteBasedConstantPropagation TOP =
		new PcodeByteBasedConstantPropagation(true, false);
	private static final PcodeByteBasedConstantPropagation BOTTOM =
		new PcodeByteBasedConstantPropagation(false, true);
	private static BytesPcodeArithmetic arithmetic;
	private static boolean isBigEndian;

	private final boolean isTop, isBottom;
	private Long value;

	/**
	 * Builds the top abstract value.
	 * 
	 * @param language base language for current program
	 */
	public PcodeByteBasedConstantPropagation(Language language) {
		this(0L, true, false);
		PcodeByteBasedConstantPropagation.arithmetic =
			BytesPcodeArithmetic.forLanguage(language);
		isBigEndian = language.isBigEndian();
	}

	private PcodeByteBasedConstantPropagation(
			Long value,
			boolean isTop,
			boolean isBottom) {
		this.value = value;
		this.isTop = isTop;
		this.isBottom = isBottom;
	}

	private PcodeByteBasedConstantPropagation(
			boolean isTop,
			boolean isBottom) {
		this(0L, isTop, isBottom);
	}

	public PcodeByteBasedConstantPropagation(
			Long value) {
		this(value, false, false);
	}

	public PcodeByteBasedConstantPropagation(
			Boolean value) {
		this(value ? 1L : 0L, false, false);
	}

	public PcodeByteBasedConstantPropagation(
			byte[] bytes,
			int size,
			boolean isBigEndian) {
		this(Utils.bytesToLong(bytes, size, isBigEndian));
	}

	@Override
	public PcodeByteBasedConstantPropagation evalNullConstant(
			ProgramPoint pp,
			SemanticOracle oracle) {
		return top();
	}

	@Override
	public PcodeByteBasedConstantPropagation evalNonNullConstant(
			Constant constant,
			ProgramPoint pp,
			SemanticOracle oracle) {
		Object cval = constant.getValue();
		if (cval instanceof Number val) {
			Type staticType = constant.getStaticType();
			if (staticType != null && staticType instanceof NumericType numType) {
				if (numType.isSigned()) {
					return new PcodeByteBasedConstantPropagation(Long.valueOf(val.longValue()));
				}
			}
		}
		if (cval instanceof Long lval) {
			return new PcodeByteBasedConstantPropagation(lval);
		}
		if (cval instanceof Integer ival) {
			return new PcodeByteBasedConstantPropagation(Integer.toUnsignedLong(ival));
		}
		if (cval instanceof Short sval) {
			return new PcodeByteBasedConstantPropagation(Short.toUnsignedLong(sval));
		}
		if (cval instanceof Byte bval) {
			return new PcodeByteBasedConstantPropagation(Byte.toUnsignedLong(bval));
		}
		if (cval instanceof Boolean bval) {
			return new PcodeByteBasedConstantPropagation(bval ? 1L : 0L);
		}
		Msg.error(this, "Unknown type for constant: " + cval);
		return top();
	}

	@Override
	public PcodeByteBasedConstantPropagation evalUnaryExpression(
			UnaryOperator operator,
			PcodeByteBasedConstantPropagation arg,
			ProgramPoint pp,
			SemanticOracle oracle) {

		if (arg.isTop()) {
			return top();
		}

		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		OpBehavior opBehavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		if (opBehavior instanceof SpecialOpBehavior) {
			// TODO
			return top();
		}

		byte[] bytes = arithmetic.unaryOp(op.getOpcode(), op.getOutput().getSize(),
			op.getInput(0).getSize(), arg.getValue(op.getInput(0).getSize()));
		return new PcodeByteBasedConstantPropagation(bytes, op.getOutput().getSize(),
			isBigEndian);
	}

	private byte[] getValue(int size) {
		return Utils.longToBytes(value, size, isBigEndian);
	}

	@Override
	public PcodeByteBasedConstantPropagation evalBinaryExpression(
			BinaryOperator operator,
			PcodeByteBasedConstantPropagation left,
			PcodeByteBasedConstantPropagation right,
			ProgramPoint pp,
			SemanticOracle oracle) {

		if ((left.isTop || right.isTop) && !left.equals(right)) {
			if (left.value == 0L || right.value == 0L) {
				if (operator instanceof PcodeBinaryOperator poperator &&
					poperator.getOp().getOpcode() == PcodeOp.INT_MULT) {
					return new PcodeByteBasedConstantPropagation(0L);
				}
			}
			return top();
		}

		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		OpBehavior opBehavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		if (opBehavior instanceof SpecialOpBehavior) {
			// TODO
			return left;
		}
		if (left.isTop) {
			return specialCaseLogic(op);
		}
		int lsize = op.getInput(0).getSize();
		int rsize = op.getInput(1).getSize();
		byte[] bytes = arithmetic.binaryOp(op.getOpcode(), op.getOutput().getSize(),
			lsize, left.getValue(lsize),
			rsize, right.getValue(rsize));
		return new PcodeByteBasedConstantPropagation(bytes, op.getOutput().getSize(),
			isBigEndian);
	}

	// These are instances that return zero when left==right.
	private PcodeByteBasedConstantPropagation specialCaseLogic(PcodeOp op) {
		int opcode = op.getOpcode();
		if (opcode == PcodeOp.INT_SUB || opcode == PcodeOp.FLOAT_SUB ||
			opcode == PcodeOp.BOOL_XOR || opcode == PcodeOp.INT_XOR) {
			return new PcodeByteBasedConstantPropagation(0L);
		}
		return top();
	}

	@Override
	public Satisfiability satisfiesBinaryExpression(
			BinaryOperator operator,
			PcodeByteBasedConstantPropagation left,
			PcodeByteBasedConstantPropagation right,
			ProgramPoint pp,
			SemanticOracle oracle) {

		if (left.isTop() || right.isTop()) {
			return Satisfiability.UNKNOWN;
		}

		if (operator instanceof ComparisonEq) {
			return left.value == right.value
					? Satisfiability.SATISFIED
					: Satisfiability.NOT_SATISFIED;
		}
		if (operator instanceof ComparisonNe) {
			return left.value != right.value
					? Satisfiability.SATISFIED
					: Satisfiability.NOT_SATISFIED;
		}
		if (operator instanceof ComparisonLe) {
			return left.value <= right.value
					? Satisfiability.SATISFIED
					: Satisfiability.NOT_SATISFIED;
		}
		if (operator instanceof ComparisonLt) {
			return left.value < right.value
					? Satisfiability.SATISFIED
					: Satisfiability.NOT_SATISFIED;
		}
		return Satisfiability.UNKNOWN;
	}

	@Override
	public ValueEnvironment<PcodeByteBasedConstantPropagation> assumeBinaryExpression(
			ValueEnvironment<PcodeByteBasedConstantPropagation> environment,
			BinaryOperator operator,
			ValueExpression left,
			ValueExpression right,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {

		if (!(operator instanceof PcodeBinaryOperator)) {
			if (operator instanceof ComparisonEq) {
				if (left instanceof Identifier leftId) {
					PcodeByteBasedConstantPropagation eval = eval(right, environment, src, oracle);
					if (eval.isBottom()) {
						return environment.bottom();
					}
					return environment.putState(leftId, eval);
				}
				else if (right instanceof Identifier rightId) {
					PcodeByteBasedConstantPropagation eval = eval(left, environment, src, oracle);
					if (eval.isBottom()) {
						return environment.bottom();
					}
					return environment.putState(rightId, eval);
				}
			}
			if (operator instanceof ComparisonNe) {
				if (left instanceof Identifier leftId) {
					PcodeByteBasedConstantPropagation eval = eval(right, environment, src, oracle);
					if (eval.isBottom()) {
						return environment.bottom();
					}
					eval.value = 1L - eval.value;
					return environment.putState(leftId, eval);
				}
				else if (right instanceof Identifier rightId) {
					PcodeByteBasedConstantPropagation eval = eval(left, environment, src, oracle);
					if (eval.isBottom()) {
						return environment.bottom();
					}
					eval.value = 1L - eval.value;
					return environment.putState(rightId, eval);
				}
			}
		}
		return environment;
	}

	@Override
	public PcodeByteBasedConstantPropagation lubAux(PcodeByteBasedConstantPropagation other)
			throws SemanticException {
		return TOP;
	}

	@Override
	public boolean lessOrEqualAux(PcodeByteBasedConstantPropagation other)
			throws SemanticException {
		return false;
	}

	@Override
	public PcodeByteBasedConstantPropagation top() {
		return TOP;
	}

	@Override
	public PcodeByteBasedConstantPropagation bottom() {
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

		return new StringRepresentation(value.toString());
	}

	@Override
	public int hashCode() {
		return Objects.hash(isBottom, isTop, value);
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
		if (!(obj instanceof PcodeByteBasedConstantPropagation other)) {
			return false;
		}

		if (isBottom != other.isBottom) {
			return false;
		}
		if (isTop != other.isTop) {
			return false;
		}
		return Objects.equals(this.value, other.value);
	}

	@Override
	public PcodeByteBasedConstantPropagation getValue(RegisterValue rv) {
		if (rv != null) {
			BigInteger val = rv.getUnsignedValue();
			if (val != null) {
				return new PcodeByteBasedConstantPropagation(val.longValue());
			}
		}
		return top();
	}
}
