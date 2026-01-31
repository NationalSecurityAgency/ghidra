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
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * A {@link BaseTaint} implementation with only two level of taintedness: clean
 * and tainted. As such, this class distinguishes values that are always clean
 * from values that are tainted in at least one execution path.
 * 
 * <p>
 * Modified to handle pcode from original source written by:
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 */
public class PcodeTaint extends BaseTaint<PcodeTaint> {

	private static final PcodeTaint TAINTED = new PcodeTaint(true);

	private static final PcodeTaint CLEAN = new PcodeTaint(false);

	private static final PcodeTaint BOTTOM = new PcodeTaint(null);

	private final Boolean taint;

	/**
	 * Builds a new instance of taint.
	 */
	public PcodeTaint() {
		this(true);
	}

	public PcodeTaint(
			Boolean taint) {
		this.taint = taint;
	}

	@Override
	protected PcodeTaint tainted() {
		return TAINTED;
	}

	@Override
	protected PcodeTaint clean() {
		return CLEAN;
	}

	@Override
	public boolean isPossiblyTainted() {
		return this == TAINTED;
	}

	@Override
	public boolean isAlwaysTainted() {
		return false;
	}

	@Override
	public StructuredRepresentation representation() {
		if (this == BOTTOM) {
			return Lattice.bottomRepresentation();
		}
		return this == TAINTED ? new StringRepresentation("#") : new StringRepresentation("_");
	}

	@Override
	public PcodeTaint top() {
		return CLEAN;
	}

	@Override
	public PcodeTaint bottom() {
		return BOTTOM;
	}

	@Override
	protected PcodeTaint defaultApprox(
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
	public PcodeTaint lub(PcodeTaint other) throws SemanticException {
		if (other == null || other.isBottom() || this.isTop() || this == other ||
			this.equals(other)) {
			return this;
		}

		if (this.isBottom()) { // || other.isTop()) 
			return other;
		}

		return lubAux(other);
	}

	@Override
	public PcodeTaint lubAux(
			PcodeTaint other)
			throws SemanticException {
		return TAINTED;
	}

	@Override
	public PcodeTaint wideningAux(
			PcodeTaint other)
			throws SemanticException {
		return TAINTED; // should never happen
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeTaint other)
			throws SemanticException {
		return false; // should never happen
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((taint == null) ? 0 : taint.hashCode());
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
		PcodeTaint other = (PcodeTaint) obj;
		if (taint == null) {
			if (other.taint != null) {
				return false;
			}
		}
		else if (!taint.equals(other.taint)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return representation().toString();
	}

}
