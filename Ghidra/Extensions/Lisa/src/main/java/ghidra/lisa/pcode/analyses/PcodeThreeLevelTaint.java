/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import ghidra.lisa.pcode.locations.PcodeLocation;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.taint.BaseTaint;
import it.unive.lisa.program.annotations.Annotation;
import it.unive.lisa.program.annotations.Annotations;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.Identifier;
import it.unive.lisa.symbolic.value.operator.binary.BinaryOperator;
import it.unive.lisa.symbolic.value.operator.ternary.TernaryOperator;
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * A {@link BaseTaint} implementation with three level of taintedness: clean,
 * tainted and top. As such, this class distinguishes values that are always
 * clean, always tainted, or tainted in at least one execution path.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 */
public class PcodeThreeLevelTaint extends BaseTaint<PcodeThreeLevelTaint> {

	private static final PcodeThreeLevelTaint TOP = new PcodeThreeLevelTaint((byte) 3);
	private static final PcodeThreeLevelTaint TAINTED = new PcodeThreeLevelTaint((byte) 2);
	private static final PcodeThreeLevelTaint CLEAN = new PcodeThreeLevelTaint((byte) 1);
	private static final PcodeThreeLevelTaint BOTTOM = new PcodeThreeLevelTaint((byte) 0);

	private final byte taint;

	/**
	 * Builds a new instance of taint.
	 */
	public PcodeThreeLevelTaint() {
		this((byte) 3);
	}

	private PcodeThreeLevelTaint(
			byte v) {
		this.taint = v;
	}

	@Override
	protected PcodeThreeLevelTaint tainted() {
		return TAINTED;
	}

	@Override
	protected PcodeThreeLevelTaint clean() {
		return CLEAN;
	}

	@Override
	public boolean isAlwaysTainted() {
		return this == TAINTED;
	}

	@Override
	public boolean isPossiblyTainted() {
		return this == TOP;
	}

	@Override
	public StructuredRepresentation representation() {
		return this == BOTTOM ? Lattice.bottomRepresentation()
				: this == CLEAN ? new StringRepresentation("_")
						: this == TAINTED ? new StringRepresentation("#")
								: Lattice.topRepresentation();
	}

	@Override
	public PcodeThreeLevelTaint top() {
		return TOP;
	}

	@Override
	public PcodeThreeLevelTaint bottom() {
		return BOTTOM;
	}

	@Override
	protected PcodeThreeLevelTaint defaultApprox(
			Identifier id,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		Annotations annots = id.getAnnotations();
		if (annots.isEmpty()) {
			return super.defaultApprox(id, pp, oracle);
		}

		if (pp.getLocation() instanceof PcodeLocation ploc) {
			for (Annotation annotation : annots) {
				String name = annotation.getAnnotationName();
				if (name.contains("@" + ploc.getAddress())) {
					if (name.contains("Tainted")) {
						return tainted();
					}

					if (name.contains("Clean")) {
						return clean();
					}
				}
			}
		}

		return bottom();
	}

	@Override
	public PcodeThreeLevelTaint evalBinaryExpression(
			BinaryOperator operator,
			PcodeThreeLevelTaint left,
			PcodeThreeLevelTaint right,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (left == TAINTED || right == TAINTED) {
			return TAINTED;
		}

		if (left == TOP || right == TOP) {
			return TOP;
		}

		return CLEAN;
	}

	@Override
	public PcodeThreeLevelTaint evalTernaryExpression(
			TernaryOperator operator,
			PcodeThreeLevelTaint left,
			PcodeThreeLevelTaint middle,
			PcodeThreeLevelTaint right,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (left == TAINTED || right == TAINTED || middle == TAINTED) {
			return TAINTED;
		}

		if (left == TOP || right == TOP || middle == TOP) {
			return TOP;
		}

		return CLEAN;
	}

	@Override
	public PcodeThreeLevelTaint lubAux(
			PcodeThreeLevelTaint other)
			throws SemanticException {
		// only happens with clean and tainted, that are not comparable
		return TOP;
	}

	@Override
	public PcodeThreeLevelTaint wideningAux(
			PcodeThreeLevelTaint other)
			throws SemanticException {
		// only happens with clean and tainted, that are not comparable
		return TOP;
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeThreeLevelTaint other)
			throws SemanticException {
		// only happens with clean and tainted, that are not comparable
		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + taint;
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
		PcodeThreeLevelTaint other = (PcodeThreeLevelTaint) obj;
		if (taint != other.taint) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return representation().toString();
	}
}
