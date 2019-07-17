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
// An example of how to open an existing Version Tracking session, manipulate some data and then
// save the session.
//@category Examples.Version Tracking

import java.util.Collection;
import java.util.List;

import ghidra.feature.vt.GhidraVersionTrackingScript;
import ghidra.feature.vt.api.main.*;

public class OpenVersionTrackingSessionScript extends GhidraVersionTrackingScript {

	@Override
	protected void run() throws Exception {
		openVersionTrackingSession("/VT__WallaceSrc__WallaceVersion2.exe");
		acceptMatchesWithGoodConfidence();
		saveVersionTrackingSession();
	}

	private void acceptMatchesWithGoodConfidence() throws Exception {
		println("Working on session: " + vtSession);

		List<VTMatchSet> matchSets = vtSession.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			println("Match set contains " + matchSet.getMatchCount() + " matches");

			//
			// Do some work here - this example is an arbitrary accepting of matches that pass an
			// arbitrary confidence level
			//
			double arbitraryValue = 10.0D;
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				VTAssociation association = match.getAssociation();
				if (association.getStatus() != VTAssociationStatus.AVAILABLE) {
					continue;
				}
				VTScore confidenceScore = match.getConfidenceScore();
				if (confidenceScore.getScore() > arbitraryValue) {
					println("\taccepting: " + match);
					association.setAccepted();
				}
				else {
					association.setRejected();
					println("\trejecting: " + match);
				}
			}
		}

	}

}
