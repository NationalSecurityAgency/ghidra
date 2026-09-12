/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.feature.vt.gui.provider.matchtable;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.filters.Filter;

/**
 * Filters matches by their stored PDiff similarity score (range [0.0, 1.0]).
 * Reads the precomputed score from the DB — no on-the-fly hash computation.
 *
 * <p>Bypass rules (always pass):
 * <ul>
 *   <li>Non-FUNCTION matches (DATA, etc.) — PDiff is only meaningful for functions</li>
 *   <li>Matches with null PDiff score — not yet computed (e.g. schema migration in progress)</li>
 * </ul>
 */
class SimilarityFilter extends AbstractDoubleRangeFilter<VTMatch> {

	SimilarityFilter() {
		super("Similarity", 0.0D, 1.0D);
	}

	@Override
	public boolean passesFilter(VTMatch t) {
		VTAssociation assoc = t.getAssociation();
		if (assoc.getType() != VTAssociationType.FUNCTION) {
			return true; // non-function matches always pass
		}
		if (t.getPdiffSimilarityScore() == null) {
			return true; // score not yet computed, don't filter out
		}
		return super.passesFilter(t);
	}

	@Override
	protected Double getFilterableValue(VTMatch t) {
		// Only called when passesFilter delegates to super, so score is non-null here.
		// Defensive 0.0 fallback just in case.
		VTScore score = t.getPdiffSimilarityScore();
		return score != null ? score.getScore() : 0.0;
	}

	@Override
	protected Filter<VTMatch> createEmptyCopy() {
		return new SimilarityFilter();
	}
}
