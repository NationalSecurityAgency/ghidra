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
package ghidra.app.plugin.core.script;

import java.util.*;

import docking.widgets.searchlist.DefaultSearchListModel;
import ghidra.app.script.ScriptInfo;

/**
 * Model for the script selection search list that organizes scripts into
 * "Recent Scripts" and "All Scripts" categories.
 */
public class ScriptsModel extends DefaultSearchListModel<ScriptInfo> {

	private List<ScriptInfo> allScripts;
	private LinkedList<String> recentScriptNames;

	public ScriptsModel(List<ScriptInfo> allScripts, LinkedList<String> recentScriptNames) {
		this.allScripts = allScripts;
		this.recentScriptNames = recentScriptNames != null ? recentScriptNames : new LinkedList<>();
		populateModel();
	}

	private void populateModel() {
		// Create map for quick lookup
		Map<String, ScriptInfo> scriptMap = new HashMap<>();
		for (ScriptInfo script : allScripts) {
			scriptMap.put(script.getName(), script);
		}

		// Add recent scripts first (in MRU order)
		List<ScriptInfo> recentScripts = new ArrayList<>();
		Set<String> addedScripts = new HashSet<>();
		for (String recentName : recentScriptNames) {
			ScriptInfo script = scriptMap.get(recentName);
			if (script != null) {
				recentScripts.add(script);
				addedScripts.add(recentName);
			}
		}

		if (!recentScripts.isEmpty()) {
			add(ScriptGroup.RECENT_SCRIPTS.getDisplayName(), recentScripts);
		}

		// Add all other scripts (alphabetically sorted)
		List<ScriptInfo> otherScripts = new ArrayList<>();
		for (ScriptInfo script : allScripts) {
			if (!addedScripts.contains(script.getName())) {
				otherScripts.add(script);
			}
		}
		otherScripts.sort(Comparator.comparing(ScriptInfo::getName));

		add(ScriptGroup.ALL_SCRIPTS.getDisplayName(), otherScripts);
	}
}
