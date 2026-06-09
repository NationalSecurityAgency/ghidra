/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.util.*;

import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.opbehavior.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import it.unive.lisa.analysis.ScopeToken;
import it.unive.lisa.analysis.SemanticException;
import it.unive.lisa.analysis.dataflow.DataflowElement;
import it.unive.lisa.analysis.dataflow.DefiniteDataflowDomain;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.program.cfg.statement.Assignment;
import it.unive.lisa.symbolic.SymbolicExpression;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.type.NumericType;
import it.unive.lisa.type.Type;
import it.unive.lisa.util.representation.*;

/**
 * An implementation of the overflow-insensitive constant propagation dataflow
 * analysis, that focuses only on integers.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 */
public class PcodeDataflowConstantPropagation implements
		DataflowElement<DefiniteDataflowDomain<PcodeDataflowConstantPropagation>, PcodeDataflowConstantPropagation> {

	private static BytesPcodeArithmetic arithmetic;
	private static boolean isBigEndian;

	private final Identifier id;
	private final Long constant;

	/**
	* Builds an empty constant propagation object.
	 * 
	 * @param language base language for current program
	*/
	public PcodeDataflowConstantPropagation(Language language) {
		this(null, null);
		PcodeDataflowConstantPropagation.arithmetic = BytesPcodeArithmetic.forLanguage(language);
		isBigEndian = language.isBigEndian();
	}

	/**
	* Builds the new constant propagation object.
	* 
	* @param id the constant variable
	* @param v  the constant value
	*/
	public PcodeDataflowConstantPropagation(
			Identifier id,
			Long v) {
		this.id = id;
		this.constant = v;
	}

	@Override
	public String toString() {
		return representation().toString();
	}

	@Override
	public Collection<Identifier> getInvolvedIdentifiers() {
		return Collections.singleton(id);
	}

	private static byte[] getValue(long val, int size) {
		return Utils.longToBytes(val, size, isBigEndian);
	}

	private static Long eval(
			SymbolicExpression e, ProgramPoint pp,
			DefiniteDataflowDomain<PcodeDataflowConstantPropagation> domain) {

		if (e instanceof Constant c) {
			Object cval = c.getValue();
			if (cval instanceof Number nval) {
				Type staticType = c.getStaticType();
				if (staticType != null && staticType instanceof NumericType numType) {
					if (numType.isSigned()) {
						return Long.valueOf(nval.longValue());
					}
				}
			}
			if (cval instanceof Long lval) {
				return lval;
			}
			if (cval instanceof Integer ival) {
				return Integer.toUnsignedLong(ival);
			}
			if (cval instanceof Short sval) {
				return Short.toUnsignedLong(sval);
			}
			if (cval instanceof Byte bval) {
				return Byte.toUnsignedLong(bval);
			}
			if (cval instanceof Boolean bval) {
				return bval ? 1L : 0L;
			}
			Msg.error(e, "Unknown type for constant: " + cval);
			return null;
		}

		if (e instanceof Identifier) {
			for (PcodeDataflowConstantPropagation cp : domain.getDataflowElements()) {
				if (cp.id.equals(e)) {
					return cp.constant;
				}
			}

			return null;
		}

		if (!(pp.getLocation() instanceof PcodeLocation ploc)) {
			return null;
		}

		PcodeOp op = ploc.op;

		if (e instanceof UnaryExpression unary) {
			OpBehavior opBehavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
			if (opBehavior instanceof SpecialOpBehavior) {
				// TODO
				return null;
			}
			Long exp = eval(unary.getExpression(), pp, domain);
			if (exp == null) {
				return exp;
			}

			byte[] bytes = arithmetic.unaryOp(op.getOpcode(), op.getOutput().getSize(),
				op.getInput(0).getSize(), getValue(exp, op.getInput(0).getSize()));
			return Utils.bytesToLong(bytes, op.getOutput().getSize(), isBigEndian);
		}

		if (e instanceof BinaryExpression binary) {
			Long right = eval(binary.getRight(), pp, domain);
			Long left = eval(binary.getLeft(), pp, domain);

			if (right == null || left == null) {
				return null;
			}

			int lsize = op.getInput(0).getSize();
			int rsize = op.getInput(1).getSize();
			byte[] bytes = arithmetic.binaryOp(op.getOpcode(), op.getOutput().getSize(),
				lsize, getValue(left, lsize),
				rsize, getValue(right, rsize));
			return Utils.bytesToLong(bytes, op.getOutput().getSize(), isBigEndian);
		}

		if (e instanceof PushAny) {
			InstLocation loc = (InstLocation) pp.getLocation();
			Function f = loc.function();
			try {
				if (f != null && pp instanceof Assignment a) {
					Program program = f.getProgram();
					Address address = program.getAddressFactory()
							.getRegisterSpace()
							.getAddress(a.getLeft().toString());
					Register r = program.getRegister(address);
					if (r != null) {
						RegisterValue rv =
							program.getProgramContext().getRegisterValue(r, f.getEntryPoint());
						if (rv != null && rv.hasValue()) {
							return rv.getUnsignedValue().longValue();
						}
					}
				}
			}
			catch (AddressFormatException e1) {
				// IGNORE
			}
		}

		return null;
	}

	@Override
	public Collection<PcodeDataflowConstantPropagation> gen(
			Identifier idg,
			ValueExpression expression,
			ProgramPoint pp,
			DefiniteDataflowDomain<PcodeDataflowConstantPropagation> domain) {
		Set<PcodeDataflowConstantPropagation> gen = new HashSet<>();

		Long v = eval(expression, pp, domain);
		if (v != null) {
			gen.add(new PcodeDataflowConstantPropagation(idg, v));
		}

		return gen;
	}

	@Override
	public Collection<PcodeDataflowConstantPropagation> gen(
			ValueExpression expression,
			ProgramPoint pp,
			DefiniteDataflowDomain<PcodeDataflowConstantPropagation> domain) {
		return Collections.emptyList();
	}

	@Override
	public Collection<PcodeDataflowConstantPropagation> kill(
			Identifier idk,
			ValueExpression expression,
			ProgramPoint pp,
			DefiniteDataflowDomain<PcodeDataflowConstantPropagation> domain) {
		Collection<PcodeDataflowConstantPropagation> result = new HashSet<>();

		for (PcodeDataflowConstantPropagation cp : domain.getDataflowElements()) {
			if (cp.id.equals(idk)) {
				result.add(cp);
			}
		}

		return result;
	}

	@Override
	public Collection<PcodeDataflowConstantPropagation> kill(
			ValueExpression expression,
			ProgramPoint pp,
			DefiniteDataflowDomain<PcodeDataflowConstantPropagation> domain) {
		return Collections.emptyList();
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, constant);
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

		PcodeDataflowConstantPropagation other = (PcodeDataflowConstantPropagation) obj;
		if (!Objects.equals(this.id, other.id)) {
			return false;
		}
		return Objects.equals(this.constant, other.constant);
	}

	@Override
	public StructuredRepresentation representation() {
		return new ListRepresentation(new StringRepresentation(id),
			new StringRepresentation(constant));
	}

	@Override
	public PcodeDataflowConstantPropagation pushScope(
			ScopeToken scope)
			throws SemanticException {
		return new PcodeDataflowConstantPropagation((Identifier) id.pushScope(scope), constant);
	}

	@Override
	public PcodeDataflowConstantPropagation popScope(
			ScopeToken scope)
			throws SemanticException {
		if (!(id instanceof OutOfScopeIdentifier)) {
			return this;
		}

		return new PcodeDataflowConstantPropagation(((OutOfScopeIdentifier) id).popScope(scope),
			constant);
	}

}
