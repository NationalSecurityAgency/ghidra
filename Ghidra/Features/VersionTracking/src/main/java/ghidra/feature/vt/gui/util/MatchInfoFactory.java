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
package ghidra.feature.vt.gui.util;

import java.util.Map.Entry;
import java.util.Set;

import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.util.datastruct.WeakValueHashMap;

public class MatchInfoFactory {

	/**
	 * Hash map with weak values. When MatchInfo is no longer held by an object,
	 * the entry is removed from the map.
	 */
	private WeakValueHashMap<VTMatch, MatchInfo> weakMap = new WeakValueHashMap<>();

	public synchronized MatchInfo getMatchInfo(VTController controller, VTMatch match,
			AddressCorrelatorManager correlator) {
		MatchInfo matchInfo = weakMap.get(match);
		if (matchInfo == null) {
			matchInfo = new MatchInfo(controller, match, correlator);
			weakMap.put(match, matchInfo);
		}
		return matchInfo;
	}

	public synchronized void clearCache() {
		weakMap.clear();
	}

	public synchronized void clearMatchInfoInternalCache() {
		for (MatchInfo info : weakMap.values()) {
			if (info != null) {
				info.clearCache();
			}
		}
	}

	/**
	 * Clear the cached match info for the given association.   This will clear the cache for
	 * multiple matches, if multiple matches exit for the given association.
	 */
	public synchronized void clearCacheForAssociation(VTAssociation association) {
		Set<Entry<VTMatch, MatchInfo>> entrySet = weakMap.entrySet();
		for (Entry<VTMatch, MatchInfo> entry : entrySet) {
			VTMatch match = entry.getKey();
			if (match.getAssociation().equals(association)) {
				MatchInfo info = entry.getValue();
				if (info != null) {
					info.clearCache();
				}
			}
		}
	}
}
