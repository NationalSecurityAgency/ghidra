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
package ghidra.feature.vt.gui.task;

import java.util.*;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.provider.impliedmatches.VTImpliedMatchInfo;
import ghidra.util.task.TaskMonitor;

public class CreateImpliedMatchesTask extends VtTask {
	private final List<VTImpliedMatchInfo> matches;
	private final VTController controller;

	private List<VTMatch> createdMatches;

	public CreateImpliedMatchesTask(VTController controller, List<VTImpliedMatchInfo> matches) {
		super("Create Implied Matches", controller.getSession());
		this.controller = controller;
		this.matches = matches;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) {
		// dedup
		Set<VTImpliedMatchInfo> set = dedupMatches();
		monitor.initialize(set.size());
		monitor.setMessage("Creating implied matches");
		VTMatchSet impliedMatchSet = controller.getSession().getImpliedMatchSet();

		List<VTMatch> result = new ArrayList<>();

		for (VTImpliedMatchInfo vtImpliedMatch : set) {
			result.add(impliedMatchSet.addMatch(vtImpliedMatch));
			monitor.incrementProgress(1);
		}
		return true;
	}

	public List<VTMatch> getCreatedMatches() {
		return Collections.unmodifiableList(createdMatches);
	}

	private Set<VTImpliedMatchInfo> dedupMatches() {
		Set<VTImpliedMatchInfo> set = new HashSet<>();
		set.addAll(matches);
		return set;
	}

}
