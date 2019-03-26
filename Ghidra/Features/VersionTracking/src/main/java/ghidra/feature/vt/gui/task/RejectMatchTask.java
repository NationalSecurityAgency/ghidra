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

import java.util.ArrayList;
import java.util.List;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RejectMatchTask extends VtTask {

	private final List<VTMatch> matches;

	public RejectMatchTask(VTSession session, List<VTMatch> matches) {
		super("Reject Matches", session);
		this.matches = matches;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		rejectMatches(monitor);
		return true;
	}

	private void rejectMatches(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Updating status for matches");
		monitor.initialize(matches.size());
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTAssociation association = match.getAssociation();
			VTAssociationStatus status = association.getStatus();
			if (status == VTAssociationStatus.ACCEPTED || status == VTAssociationStatus.REJECTED) {
				continue;
			}
			try {
				association.setRejected();
			}
			catch (VTAssociationStatusException e) {
				throw new AssertException("Should have been given an association that is not " +
					"blocked - current status: " + association.getStatus());
			}
			monitor.incrementProgress(1);
		}

		monitor.setProgress(matches.size());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ErrorStatus {
		private List<Exception> exceptions = new ArrayList<>();

		boolean hasErrors() {
			return exceptions.size() > 0;
		}
	}
}
