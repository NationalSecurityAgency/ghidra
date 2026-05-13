/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.value.ValueDomain;

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
public class PcodePentagonLowX86 extends PcodePentagon {

	/**
	 * Builds the PcodePentagons.
	 */
	public PcodePentagonLowX86() {
		this.intervals = new ValueEnvironment<>(new PcodeIntervalLowX86()).top();
		this.upperBounds = new ValueEnvironment<>(new PcodeUpperBounds(true)).top();
	}

}
