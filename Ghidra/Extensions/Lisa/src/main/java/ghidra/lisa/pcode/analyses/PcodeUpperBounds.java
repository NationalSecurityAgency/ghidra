/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.util.*;

import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.program.model.lang.RegisterValue;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalValueDomain;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.Identifier;
import it.unive.lisa.symbolic.value.ValueExpression;
import it.unive.lisa.symbolic.value.operator.binary.*;
import it.unive.lisa.util.representation.*;

/**
 * The upper bounds abstract domain. It is implemented as a
 * {@link BaseNonRelationalValueDomain}.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 * @author <a href="mailto:vincenzo.arceri@unipr.it">Vincenzo Arceri</a>
 */
public class PcodeUpperBounds
		implements PcodeNonRelationalValueDomain<PcodeUpperBounds>, Iterable<Identifier> {

	/**
	 * The abstract top element.
	 */
	private static final PcodeUpperBounds TOP = new PcodeUpperBounds(true);

	/**
	 * The abstract bottom element.
	 */
	private static final PcodeUpperBounds BOTTOM = new PcodeUpperBounds(new TreeSet<>());

	/**
	 * The flag to set abstract top state.
	 */
	private final boolean isTop;

	/**
	 * The set containing the bounds.
	 */
	private final Set<Identifier> bounds;

	/**
	 * Builds the upper bounds.
	 */
	public PcodeUpperBounds() {
		this(true);
	}

	/**
	 * Builds the upper bounds.
	 * 
	 * @param isTop {@code true} if the abstract domain is top; otherwise
	 *                  {@code false}.
	 */
	public PcodeUpperBounds(
			boolean isTop) {
		this.bounds = null;
		this.isTop = isTop;
	}

	/**
	 * Builds the upper bounds.
	 * 
	 * @param bounds the bounds to set
	 */
	public PcodeUpperBounds(
			Set<Identifier> bounds) {
		this.bounds = bounds;
		this.isTop = false;
	}

	@Override
	public StructuredRepresentation representation() {
		if (isTop()) {
			return new StringRepresentation("{}");
		}
		if (isBottom()) {
			return Lattice.bottomRepresentation();
		}
		return new SetRepresentation(bounds, StringRepresentation::new);
	}

	@Override
	public PcodeUpperBounds top() {
		return TOP;
	}

	@Override
	public PcodeUpperBounds bottom() {
		return BOTTOM;
	}

	@Override
	public boolean isBottom() {
		return !isTop && bounds.isEmpty();
	}

	@Override
	public PcodeUpperBounds lubAux(
			PcodeUpperBounds other)
			throws SemanticException {
		Set<Identifier> lub = new HashSet<>(bounds);
		lub.retainAll(other.bounds);
		return new PcodeUpperBounds(lub);
	}

	@Override
	public PcodeUpperBounds glbAux(
			PcodeUpperBounds other)
			throws SemanticException {
		Set<Identifier> lub = new HashSet<>(bounds);
		lub.addAll(other.bounds);
		return new PcodeUpperBounds(lub);
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeUpperBounds other)
			throws SemanticException {
		return bounds.containsAll(other.bounds);
	}

	@Override
	public PcodeUpperBounds wideningAux(
			PcodeUpperBounds other)
			throws SemanticException {
		return other.bounds.containsAll(bounds) ? other : TOP;
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
		PcodeUpperBounds other = (PcodeUpperBounds) obj;
		return Objects.equals(bounds, other.bounds) && isTop == other.isTop;
	}

	@Override
	public int hashCode() {
		return Objects.hash(bounds, isTop);
	}

	@Override
	public ValueEnvironment<PcodeUpperBounds> assumeBinaryExpression(
			ValueEnvironment<PcodeUpperBounds> environment,
			BinaryOperator operator,
			ValueExpression left,
			ValueExpression right,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {
		if (!(left instanceof Identifier x && right instanceof Identifier y)) {
			return environment;
		}

		// glb is the union!

		if (!(operator instanceof PcodeBinaryOperator)) {
			if (operator instanceof ComparisonEq) {
				// x == y
				PcodeUpperBounds set = environment.getState(x).glb(environment.getState(y));
				return environment.putState(x, set).putState(y, set);
			}

			if (operator instanceof ComparisonLt) {
				// x < y
				PcodeUpperBounds set = environment.getState(x)
						.glb(environment.getState(y))
						.glb(new PcodeUpperBounds(Collections.singleton(y)));
				return environment.putState(x, set);
			}

			if (operator instanceof ComparisonLe) {
				// x <= y
				PcodeUpperBounds set = environment.getState(x).glb(environment.getState(y));
				return environment.putState(x, set);
			}
		}

		return environment;
	}

	@Override
	public Iterator<Identifier> iterator() {
		if (bounds == null) {
			return Collections.emptyIterator();
		}
		return bounds.iterator();
	}

	/**
	 * Checks if this bounds contains a specified identifier of a program
	 * variable.
	 * 
	 * @param id the identifier to check
	 * 
	 * @return {@code true} if this bounds contains the specified identifier;
	 *             otherwise, {@code false}.
	 */
	public boolean contains(
			Identifier id) {
		return bounds != null && bounds.contains(id);
	}

	/**
	 * Adds the specified identifier of a program variable in the bounds.
	 * 
	 * @param id the identifier to add in the bounds.
	 * 
	 * @return the updated bounds.
	 */
	public PcodeUpperBounds add(
			Identifier id) {
		Set<Identifier> res = new HashSet<>();
		if (!isTop() && !isBottom()) {
			res.addAll(bounds);
		}
		res.add(id);
		return new PcodeUpperBounds(res);
	}

	@Override
	public PcodeUpperBounds getValue(RegisterValue rv) {
		return top();
	}
}
