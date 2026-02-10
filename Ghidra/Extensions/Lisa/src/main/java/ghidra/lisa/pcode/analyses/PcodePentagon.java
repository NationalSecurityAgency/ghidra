/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import org.apache.commons.collections4.CollectionUtils;

import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.Satisfiability;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.value.ValueDomain;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.util.numeric.MathNumber;
import it.unive.lisa.util.representation.*;

/**
 * /** The pentagons abstract domain, a weakly relational numeric abstract
 * domain. This abstract domain captures properties of the form of x \in [a, b]
 * &and; x &lt; y. It is more precise than the well known interval domain, but
 * it is less precise than the octagon domain. It is implemented as a
 * {@link ValueDomain}.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 * @author <a href="mailto:vincenzo.arceri@unipr.it">Vincenzo Arceri</a>
 * 
 * <p>
 * @see <a href=
 *          "https://www.sciencedirect.com/science/article/pii/S0167642309000719?ref=cra_js_challenge&fr=RR-1">Pentagons:
 *          A weakly relational abstract domain for the efficient validation of
 *          array accesses</a>
 */
public class PcodePentagon implements ValueDomain<PcodePentagon>, BaseLattice<PcodePentagon> {

	/**
	 * The interval environment.
	 */
	protected ValueEnvironment<PcodeInterval> intervals;

	/**
	 * The upper bounds environment.
	 */
	protected ValueEnvironment<PcodeUpperBounds> upperBounds;

	/**
	 * Builds the PcodePentagons.
	 */
	public PcodePentagon() {
		this.intervals = new ValueEnvironment<>(new PcodeInterval()).top();
		this.upperBounds = new ValueEnvironment<>(new PcodeUpperBounds(true)).top();
	}

	/**
	 * Builds the pentagons.
	 * 
	 * @param intervals   the interval environment
	 * @param upperBounds the upper bounds environment
	 */
	public PcodePentagon(
			ValueEnvironment<PcodeInterval> intervals,
			ValueEnvironment<PcodeUpperBounds> upperBounds) {
		this.intervals = intervals;
		this.upperBounds = upperBounds;
	}

	@Override
	public PcodePentagon assign(
			Identifier id,
			ValueExpression expression,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		ValueEnvironment<PcodeUpperBounds> newBounds =
			getUpperBounds().assign(id, expression, pp, oracle);
		ValueEnvironment<PcodeInterval> newIntervals =
			getIntervals().assign(id, expression, pp, oracle);

		// we add the semantics for assignments here as we have access to the
		// whole assignment
		if (expression instanceof BinaryExpression) {
			BinaryExpression be = (BinaryExpression) expression;
			PcodeLocation ploc = (PcodeLocation) pp.getLocation();
			PcodeOp op = ploc.op;
			int opcode = op.getOpcode();
			if (opcode == PcodeOp.INT_SUB || opcode == PcodeOp.FLOAT_SUB) {
				if (be.getLeft() instanceof Identifier x) {
					if (be.getRight() instanceof Constant) {
						// r = x - c
						newBounds = newBounds.putState(id, getUpperBounds().getState(x).add(x));
					}
					else if (be.getRight() instanceof Identifier) {
						// r = x - y
						Identifier y = (Identifier) be.getRight();

						if (newBounds.getState(y).contains(x)) {
							newIntervals = newIntervals.putState(id, newIntervals.getState(id)
									.glb(new PcodeInterval(MathNumber.ZERO,
										MathNumber.PLUS_INFINITY)));  // was MathNumber.ONE
						}
					}
				}
			}
			else if ((opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM) &&
				be.getRight() instanceof Identifier d) {
				// r = u % d
				MathNumber low = getIntervals().getState(d).interval.getLow();
				if (low.isPositive() || low.isZero()) {
					newBounds =
						newBounds.putState(id, new PcodeUpperBounds(Collections.singleton(d)));
				}
				else {
					newBounds = newBounds.putState(id, new PcodeUpperBounds().top());
				}
			}
		}

		return new PcodePentagon(
			newIntervals,
			newBounds).closure();
	}

	@Override
	public PcodePentagon smallStepSemantics(
			ValueExpression expression,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return new PcodePentagon(
			getIntervals().smallStepSemantics(expression, pp, oracle),
			getUpperBounds().smallStepSemantics(expression, pp, oracle));
	}

	@Override
	public PcodePentagon assume(
			ValueExpression expression,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {
		return new PcodePentagon(
			getIntervals().assume(expression, src, dest, oracle),
			getUpperBounds().assume(expression, src, dest, oracle));
	}

	@Override
	public PcodePentagon forgetIdentifier(
			Identifier id)
			throws SemanticException {
		return new PcodePentagon(
			getIntervals().forgetIdentifier(id),
			getUpperBounds().forgetIdentifier(id));
	}

	@Override
	public PcodePentagon forgetIdentifiersIf(
			Predicate<Identifier> test)
			throws SemanticException {
		return new PcodePentagon(
			getIntervals().forgetIdentifiersIf(test),
			getUpperBounds().forgetIdentifiersIf(test));
	}

	@Override
	public Satisfiability satisfies(
			ValueExpression expression,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return getIntervals().satisfies(expression, pp, oracle)
				.glb(getUpperBounds().satisfies(expression, pp, oracle));
	}

	@Override
	public PcodePentagon pushScope(
			ScopeToken token)
			throws SemanticException {
		return new PcodePentagon(getIntervals().pushScope(token),
			getUpperBounds().pushScope(token));
	}

	@Override
	public PcodePentagon popScope(
			ScopeToken token)
			throws SemanticException {
		return new PcodePentagon(getIntervals().popScope(token), getUpperBounds().popScope(token));
	}

	@Override
	public StructuredRepresentation representation() {
		if (isTop())
			return Lattice.topRepresentation();
		if (isBottom())
			return Lattice.bottomRepresentation();
		Map<StructuredRepresentation, StructuredRepresentation> mapping = new HashMap<>();
		for (Identifier id : CollectionUtils.union(getIntervals().getKeys(),
			getUpperBounds().getKeys())) {
			mapping.put(new StringRepresentation(id),
				new StringRepresentation(getIntervals().getState(id).toString() + ", " +
					getUpperBounds().getState(id).representation()));
		}
		return new MapRepresentation(mapping);
	}

	@Override
	public PcodePentagon top() {
		return new PcodePentagon(getIntervals().top(), getUpperBounds().top());
	}

	@Override
	public boolean isTop() {
		return getIntervals().isTop() && getUpperBounds().isTop();
	}

	@Override
	public PcodePentagon bottom() {
		return new PcodePentagon(getIntervals().bottom(), getUpperBounds().bottom());
	}

	@Override
	public boolean isBottom() {
		return getIntervals().isBottom() && getUpperBounds().isBottom();
	}

	private PcodePentagon closure() throws SemanticException {
		ValueEnvironment<PcodeUpperBounds> newBounds = new ValueEnvironment<PcodeUpperBounds>(
			getUpperBounds().lattice, getUpperBounds().getMap());

		for (Identifier id1 : getIntervals().getKeys()) {
			Set<Identifier> closure = new HashSet<>();
			for (Identifier id2 : getIntervals().getKeys()) {
				if (!id1.equals(id2)) {
					PcodeInterval state1 = getIntervals().getState(id1);
					LongInterval interval1 = state1.interval;
					PcodeInterval state2 = getIntervals().getState(id2);
					LongInterval interval2 = state2.interval;
					if (interval1 != null && interval2 != null) {
						if (interval1.getHigh().compareTo(interval2.getLow()) < 0) {
							closure.add(id2);
						}
					}
					else {
						Msg.error(this, "Unexpected combination: " + state1 + " : " + state2);
					}
				}
			}
			if (!closure.isEmpty()) {
				// glb is the union
				newBounds = newBounds.putState(id1,
					newBounds.getState(id1).glb(new PcodeUpperBounds(closure)));
			}

		}

		return new PcodePentagon(getIntervals(), newBounds);
	}

	@Override
	public PcodePentagon lubAux(
			PcodePentagon other)
			throws SemanticException {
		ValueEnvironment<PcodeUpperBounds> newBounds = getUpperBounds().lub(other.getUpperBounds());
		for (Entry<Identifier, PcodeUpperBounds> entry : getUpperBounds()) {
			Set<Identifier> closure = new HashSet<>();
			for (Identifier bound : entry.getValue()) {
				PcodeInterval entryState = other.getIntervals().getState(entry.getKey());
				LongInterval entryInterval = entryState.interval;
				PcodeInterval boundsState = other.getIntervals().getState(bound);
				LongInterval boundsInterval = boundsState.interval;
				if (entryInterval != null && boundsInterval != null) {
					if (entryInterval.getHigh().compareTo(boundsInterval.getLow()) < 0) {
						closure.add(bound);
					}
				}
				else {
					Msg.error(this, "Unexpected combination: " + entryState + " : " + boundsState);
				}
			}
			if (!closure.isEmpty()) {
				// glb is the union
				newBounds = newBounds.putState(entry.getKey(),
					newBounds.getState(entry.getKey()).glb(new PcodeUpperBounds(closure)));
			}
		}

		for (Entry<Identifier, PcodeUpperBounds> entry : other.getUpperBounds()) {
			Set<Identifier> closure = new HashSet<>();
			for (Identifier bound : entry.getValue()) {
				PcodeInterval entryState = getIntervals().getState(entry.getKey());
				LongInterval entryInterval = entryState.interval;
				PcodeInterval boundsState = getIntervals().getState(bound);
				LongInterval boundsInterval = boundsState.interval;
				if (entryInterval != null && boundsInterval != null) {
					if (entryInterval.getHigh().compareTo(boundsInterval.getLow()) < 0) {
						closure.add(bound);
					}
				}
				else {
					Msg.error(this, "Unexpected combination: " + entryState + " : " + boundsState);
				}
			}
			if (!closure.isEmpty()) {
				// glb is the union
				newBounds = newBounds.putState(entry.getKey(),
					newBounds.getState(entry.getKey()).glb(new PcodeUpperBounds(closure)));
			}
		}

		return new PcodePentagon(getIntervals().lub(other.getIntervals()), newBounds);
	}

	@Override
	public PcodePentagon wideningAux(
			PcodePentagon other)
			throws SemanticException {
		return new PcodePentagon(getIntervals().widening(other.getIntervals()),
			getUpperBounds().widening(other.getUpperBounds()));
	}

	@Override
	public boolean lessOrEqualAux(
			PcodePentagon other)
			throws SemanticException {
		if (!getIntervals().lessOrEqual(other.getIntervals())) {
			return false;
		}
		for (Entry<Identifier, PcodeUpperBounds> entry : other.getUpperBounds()) {
			for (Identifier bound : entry.getValue()) {
				if (!(getUpperBounds().getState(entry.getKey()).contains(bound) ||
					getIntervals().getState(entry.getKey()).interval.getHigh()
							.compareTo(getIntervals().getState(bound).interval.getLow()) < 0)) {
					return false;
				}
			}
		}

		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getIntervals(), getUpperBounds());
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
		PcodePentagon other = (PcodePentagon) obj;
		return Objects.equals(getIntervals(), other.getIntervals()) &&
			Objects.equals(getUpperBounds(), other.getUpperBounds());
	}

	@Override
	public String toString() {
		return representation().toString();
	}

	@Override
	public boolean knowsIdentifier(
			Identifier id) {
		return getIntervals().knowsIdentifier(id) || getUpperBounds().knowsIdentifier(id);
	}

	public ValueEnvironment<PcodeInterval> getIntervals() {
		return intervals;
	}

	public ValueEnvironment<PcodeUpperBounds> getUpperBounds() {
		return upperBounds;
	}
}
