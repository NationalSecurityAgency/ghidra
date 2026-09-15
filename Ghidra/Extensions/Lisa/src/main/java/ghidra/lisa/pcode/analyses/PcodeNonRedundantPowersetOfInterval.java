/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.util.*;

import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import it.unive.lisa.analysis.SemanticException;
import it.unive.lisa.analysis.SemanticOracle;
import it.unive.lisa.analysis.nonRedundantSet.NonRedundantPowersetOfBaseNonRelationalValueDomain;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.numeric.Interval;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.Identifier;
import it.unive.lisa.symbolic.value.ValueExpression;
import it.unive.lisa.symbolic.value.operator.binary.*;
import it.unive.lisa.util.numeric.MathNumber;

/**
 * The finite non redundant powerset of {@link Interval} abstract domain
 * approximating numeric values as a non redundant set of interval. It is
 * implemented as a {@link NonRedundantPowersetOfBaseNonRelationalValueDomain},
 * which handles most of the basic operation (such as
 * {@link NonRedundantPowersetOfBaseNonRelationalValueDomain#lubAux lub},
 * {@link NonRedundantPowersetOfBaseNonRelationalValueDomain#glbAux glb},
 * {@link NonRedundantPowersetOfBaseNonRelationalValueDomain#wideningAux
 * widening} and others operations needed to calculate the previous ones).
 */
public class PcodeNonRedundantPowersetOfInterval
		extends
		NonRedundantPowersetOfBaseNonRelationalValueDomain<PcodeNonRedundantPowersetOfInterval, PcodeInterval> {

	/**
	 * Constructs an empty non redundant set of intervals.
	 */
	public PcodeNonRedundantPowersetOfInterval() {
		super(new TreeSet<>(), PcodeInterval.BOTTOM);
	}

	/**
	 * Constructs a non redundant set of intervals with the given intervals.
	 * 
	 * @param elements the set of intervals
	 */
	public PcodeNonRedundantPowersetOfInterval(
			SortedSet<PcodeInterval> elements) {
		super(elements, PcodeInterval.BOTTOM);
	}

	/**
	 * This specific Egli-Milner connector follows this definition:<br>
	 * given two subsets S<sub>1</sub> and S<sub>2</sub> of a domain of a
	 * lattice:
	 * <p>
	 * S<sub>1</sub> +<sub>EM</sub> S<sub>2</sub> = {s<sub>2</sub> &ni;
	 * S<sub>2</sub> | &exist; s<sub>1</sub> &ni; S<sub>1</sub> : s<sub>1</sub>
	 * &le; s<sub>2</sub>} &cup; {lub(s'<sub>1</sub>, s<sub>2</sub>) |
	 * s'<sub>1</sub> &ni; S<sub>1</sub>, s<sub>2</sub> &ni; S<sub>2</sub>, NOT
	 * &exist; s<sub>1</sub> &ni; S<sub>1</sub> : s<sub>1</sub> &le;
	 * s<sub>2</sub>}
	 * </p>
	 * s'<sub>1</sub> can be chosen randomly but in this case is chosen to be
	 * the closest interval to s<sub>2</sub> (closest based on
	 * {@link #middlePoint(PcodeInterval) middle point}).
	 */
	@Override
	protected PcodeNonRedundantPowersetOfInterval EgliMilnerConnector(
			PcodeNonRedundantPowersetOfInterval other)
			throws SemanticException {
		SortedSet<PcodeInterval> newElementsSet = new TreeSet<>();
		SortedSet<PcodeInterval> notCoverSet = new TreeSet<>();

		// first side of the union
		for (PcodeInterval s2 : other.elementsSet) {
			boolean existsLower = false;
			for (PcodeInterval s1 : elementsSet) {
				if (s1.lessOrEqual(s2)) {
					existsLower = true;
					break;
				}
			}
			if (existsLower) {
				newElementsSet.add(s2);
			}
			else {
				notCoverSet.add(s2);
			}
		}

		// second side of the union
		for (PcodeInterval s2 : notCoverSet) {
			MathNumber middlePoint = middlePoint(s2);
			MathNumber closestValue = middlePoint;
			MathNumber closestDiff = closestValue.subtract(middlePoint).abs();
			PcodeInterval closest = PcodeInterval.TOP;
			for (PcodeInterval s1 : elementsSet) {
				if (closestValue.compareTo(middlePoint) == 0) {
					closest = s1;
					closestValue = middlePoint(s1);
					closestDiff = closestValue.subtract(middlePoint).abs();
				}
				else {
					MathNumber s1Diff = middlePoint(s1).subtract(middlePoint).abs();
					if (s1Diff.compareTo(closestDiff) < 0) {
						closest = s1;
						closestValue = middlePoint(s1);
						closestDiff = closestValue.subtract(middlePoint).abs();
					}
				}
			}
			newElementsSet.add(s2.lub(closest));
		}
		return new PcodeNonRedundantPowersetOfInterval(newElementsSet).removeRedundancy()
				.removeOverlapping();
	}

	/**
	 * Yields the middle point of an {@link Interval}. If both extremes are
	 * non-infinite the middle point is the sum of the two divided by two. If
	 * only one of the two extreme is infinite the middle point is said to be
	 * the non-infinite extreme. If both the extremes are infinite the middle
	 * point is said to be 0.
	 * 
	 * @param interval the interval to calculate the middle point of
	 * 
	 * @return the middle point of the interval
	 */
	protected MathNumber middlePoint(
			PcodeInterval interval) {
		if (interval.interval.isFinite()) {
			return interval.interval.getLow()
					.add(interval.interval.getHigh())
					.divide(new MathNumber(2));
		}
		else if (interval.interval.getHigh().isFinite() && !interval.interval.getLow().isFinite()) {
			return interval.interval.getHigh();
		}
		else if (!interval.interval.getHigh().isFinite() && interval.interval.getLow().isFinite()) {
			return interval.interval.getLow().subtract(MathNumber.ONE);
		}
		// both infinite
		return MathNumber.ZERO;
	}

	@Override
	public ValueEnvironment<PcodeNonRedundantPowersetOfInterval> assumeBinaryExpression(
			ValueEnvironment<PcodeNonRedundantPowersetOfInterval> environment,
			BinaryOperator operator,
			ValueExpression left,
			ValueExpression right,
			ProgramPoint src,
			ProgramPoint dest,
			SemanticOracle oracle)
			throws SemanticException {
		Identifier id;
		PcodeNonRedundantPowersetOfInterval eval;
		boolean rightIsExpr;
		if (left instanceof Identifier leftId) {
			eval = eval(right, environment, src, oracle);
			id = leftId;
			rightIsExpr = true;
		}
		else if (right instanceof Identifier rightId) {
			eval = eval(left, environment, src, oracle);
			id = rightId;
			rightIsExpr = false;
		}
		else {
			return environment;
		}

		PcodeNonRedundantPowersetOfInterval starting = environment.getState(id);
		if (eval.isBottom() || starting.isBottom()) {
			return environment.bottom();
		}

		SortedSet<PcodeInterval> newSet = new TreeSet<>();

		for (PcodeInterval startingInterval : starting.elementsSet)
			for (PcodeInterval interval : eval.elementsSet) {
				boolean lowIsMinusInfinity = interval.interval.lowIsMinusInfinity();
				PcodeInterval lowInf =
					new PcodeInterval(interval.interval.getLow(), MathNumber.PLUS_INFINITY);
				PcodeInterval lowp1Inf =
					new PcodeInterval(interval.interval.getLow().add(MathNumber.ONE),
					MathNumber.PLUS_INFINITY);
				PcodeInterval infHigh =
					new PcodeInterval(MathNumber.MINUS_INFINITY, interval.interval.getHigh());
				PcodeInterval infHighm1 = new PcodeInterval(MathNumber.MINUS_INFINITY,
					interval.interval.getHigh().subtract(MathNumber.ONE));

				if (!(operator instanceof PcodeBinaryOperator)) {
					if (operator instanceof ComparisonEq) {
						newSet.add(interval);
					}
					else if (operator instanceof ComparisonLe) {
						if (rightIsExpr) {
							newSet.add(startingInterval.glb(infHigh));
						}
						else if (lowIsMinusInfinity) {
							newSet.add(startingInterval);
						}
						else {
							newSet.add(startingInterval.glb(lowInf));
						}
					}
					else if (operator instanceof ComparisonLt) {
						if (rightIsExpr) {
							newSet.add(
								lowIsMinusInfinity ? interval : startingInterval.glb(infHighm1));
						}
						else if (lowIsMinusInfinity) {
							newSet.add(startingInterval);
						}
						else {
							newSet.add(startingInterval.glb(lowp1Inf));
						}
					}
					else {
						newSet.add(startingInterval);
					}
				}
			}

		PcodeNonRedundantPowersetOfInterval intervals =
			new PcodeNonRedundantPowersetOfInterval(newSet)
					.removeRedundancy()
					.removeOverlapping();
		if (intervals.isBottom()) {
			return environment.bottom();
		}
		return environment.putState(id, intervals);
	}

	@Override
	protected PcodeNonRedundantPowersetOfInterval mk(
			SortedSet<PcodeInterval> elements) {
		return new PcodeNonRedundantPowersetOfInterval(elements);
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
		PcodeNonRedundantPowersetOfInterval other = (PcodeNonRedundantPowersetOfInterval) obj;
		if (!Objects.equals(this.elementsSet, other.elementsSet)) {
			return false;
		}
		return Objects.equals(this.valueDomain, other.valueDomain);
	}
}
