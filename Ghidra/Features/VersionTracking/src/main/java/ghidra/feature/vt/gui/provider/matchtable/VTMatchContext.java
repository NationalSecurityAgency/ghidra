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

import java.util.ArrayList;
import java.util.List;

import docking.DefaultActionContext;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTSession;

public class VTMatchContext extends DefaultActionContext {

	private final List<VTMatch> selectedMatches;
	private final VTSession session;

	public VTMatchContext(VTMatchTableProvider provider, List<VTMatch> selectedMatches,
			VTSession session) {
		super(provider, null);
		this.selectedMatches = selectedMatches;
		this.session = session;
	}

	public List<VTMatch> getSelectedMatches() {
		return selectedMatches;
	}

	public int getSelectedRowCount() {
		return selectedMatches.size();
	}

	public VTSession getSession() {
		return session;
	}

	public List<VTMatch> getFunctionMatches() {
		List<VTMatch> functionMatches = new ArrayList<>();

		for (VTMatch match : selectedMatches) {
			VTAssociation association = match.getAssociation();
			if (association.getType() != VTAssociationType.FUNCTION) {
				continue;
			}

			functionMatches.add(match);
		}
		return functionMatches;
	}
}
