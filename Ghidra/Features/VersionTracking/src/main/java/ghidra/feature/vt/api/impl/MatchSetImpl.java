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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.correlator.program.ImpliedMatchProgramCorrelator;
import ghidra.feature.vt.api.correlator.program.ManualMatchProgramCorrelator;
import ghidra.feature.vt.api.main.*;
import ghidra.program.model.address.Address;

import java.util.*;

public class MatchSetImpl implements VTMatchSet {
	private ProgramCorrelatorInfoFake correlatorInfo;
	private final VTSession session;

	public MatchSetImpl(VTSession session, String name) {
		this.session = session;
		correlatorInfo = new ProgramCorrelatorInfoFake(name);
	}

	@Override
	public VTMatch addMatch(VTMatchInfo match) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getID() {
		return 0;
	}

	@Override
	public int getMatchCount() {
		return 0;
	}

	@Override
	public VTSession getSession() {
		return session;
	}

	@Override
	public Collection<VTMatch> getMatches() {
		return Collections.emptyList();
	}

	@Override
	public Collection<VTMatch> getMatches(Address sourceAddress, Address destinationAddress) {
		return Collections.emptyList();
	}

	@Override
	public Collection<VTMatch> getMatches(VTAssociation association) {
		return new ArrayList<VTMatch>();
	}

	@Override
	public VTProgramCorrelatorInfo getProgramCorrelatorInfo() {
		return correlatorInfo;
	}

	@Override
	public boolean removeMatch(VTMatch match) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasRemovableMatches() {
		VTProgramCorrelatorInfo info = getProgramCorrelatorInfo();
		String correlatorClassName = info.getCorrelatorClassName();
		return correlatorClassName.equals(ManualMatchProgramCorrelator.class.getName()) ||
			correlatorClassName.equals(ImpliedMatchProgramCorrelator.class.getName());
	}

	@Override
	public String toString() {
		return "Match Set " + getID() + " - " + getMatchCount() + " matches [Correlator=" +
			getProgramCorrelatorInfo().getName() + "]";
	}
}
