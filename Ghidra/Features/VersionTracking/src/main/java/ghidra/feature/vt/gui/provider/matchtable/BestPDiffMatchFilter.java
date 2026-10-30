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

import java.util.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.filters.Filter;
import ghidra.framework.options.SaveState;

/**
 * Filter that deduplicates matches across correlators. When enabled, keeps only
 * the single best match per (source address, destination address) pair.
 * "Best" means highest confidence score; ties broken by lowest match-set ID.
 *
 * <p>Exact name matches and combined reference matches are excluded from
 * deduplication and always pass the filter.</p>
 */
public class BestPDiffMatchFilter extends Filter<VTMatch> {

	private static final String STATE_KEY = "BestPDiffMatchFilter.enabled";

	/** Correlators whose matches are always hidden when this filter is enabled. */
	private static final Set<String> HIDDEN_CORRELATORS = Set.of(
		"Combined Function and Data Reference Match");

	private GCheckBox checkBox;
	private JComponent component;

	/**
	 * Lazy cache: "srcAddr|dstAddr" → winning match info.
	 * We store the match-set ID and confidence (not the VTMatch object) because
	 * the table model may hold different object instances than the session returns.
	 */
	private Map<String, BestMatchInfo> bestMatchCache;

	public BestPDiffMatchFilter() {
		checkBox = new GCheckBox("Best (PDiff)", false);
		checkBox.setToolTipText(
			"Best PDiff Match — show only the best match per function pair (deduplicate across correlators)");
		checkBox.addItemListener(e -> {
			invalidateCache();
			fireStatusChanged(getFilterStatus());
		});

		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
		panel.add(checkBox);
		component = panel;
	}

	private void invalidateCache() {
		bestMatchCache = null;
	}

	private static String getCorrelatorName(VTMatchSet matchSet) {
		return matchSet.getProgramCorrelatorInfo().getName();
	}

	private void buildCache(VTMatch anyMatch) {
		bestMatchCache = new HashMap<>();

		VTSession session = anyMatch.getMatchSet().getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();

		for (VTMatchSet matchSet : matchSets) {
			// Hidden correlators don't participate in deduplication
			if (HIDDEN_CORRELATORS.contains(getCorrelatorName(matchSet))) {
				continue;
			}

			int setId = matchSet.getID();
			for (VTMatch match : matchSet.getMatches()) {
				VTAssociation assoc = match.getAssociation();
				String key = assoc.getSourceAddress() + "|" + assoc.getDestinationAddress();

				BestMatchInfo current = bestMatchCache.get(key);
				double conf = match.getConfidenceScore().getScore();

				if (current == null || conf > current.confidence ||
						(conf == current.confidence && setId < current.matchSetId)) {
					bestMatchCache.put(key, new BestMatchInfo(setId, conf));
				}
			}
		}
	}

	@Override
	public boolean passesFilter(VTMatch t) {
		if (!checkBox.isSelected()) {
			return true;
		}

		String name = getCorrelatorName(t.getMatchSet());

		// Hidden correlators are always filtered out
		if (HIDDEN_CORRELATORS.contains(name)) {
			return false;
		}

		if (bestMatchCache == null) {
			buildCache(t);
		}

		VTAssociation assoc = t.getAssociation();
		String key = assoc.getSourceAddress() + "|" + assoc.getDestinationAddress();
		BestMatchInfo best = bestMatchCache.get(key);
		if (best == null) {
			return true;
		}

		// Pass if this match is from the winning match set with the winning confidence
		int matchSetId = t.getMatchSet().getID();
		double conf = t.getConfidenceScore().getScore();
		return matchSetId == best.matchSetId && conf == best.confidence;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		if (checkBox.isSelected()) {
			return FilterEditingStatus.APPLIED;
		}
		return FilterEditingStatus.NONE;
	}

	@Override
	public FilterShortcutState getFilterShortcutState() {
		if (!checkBox.isSelected()) {
			return FilterShortcutState.ALWAYS_PASSES;
		}
		return FilterShortcutState.REQUIRES_CHECK;
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putBoolean(STATE_KEY, checkBox.isSelected());
	}

	@Override
	public void readConfigState(SaveState saveState) {
		checkBox.setSelected(saveState.getBoolean(STATE_KEY, false));
	}

	@Override
	public boolean isSubFilterOf(Filter<VTMatch> otherFilter) {
		if (!(otherFilter instanceof BestPDiffMatchFilter other)) {
			return false;
		}
		return checkBox.isSelected() || !other.checkBox.isSelected();
	}

	@Override
	protected Filter<VTMatch> createEmptyCopy() {
		return new BestPDiffMatchFilter();
	}

	private static class BestMatchInfo {
		final int matchSetId;
		final double confidence;

		BestMatchInfo(int matchSetId, double confidence) {
			this.matchSetId = matchSetId;
			this.confidence = confidence;
		}
	}
}
