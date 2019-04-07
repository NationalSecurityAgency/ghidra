/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.main;

import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.program.model.address.Address;

import java.util.Collection;

/**
 * Interface for all the matches generated from a single program correlator run.
 *
 */
public interface VTMatchSet {

	/**
	 * Returns the VTSession that contains this match set.
	 * @return the VTSession that contains this match set.
	 */
	public VTSession getSession();

	/**
	 * Creates a match based on the given info and adds it to this match set.
	 * 
	 * @param info the info for the match to add to this match set.
	 * @return the new VTMatch that was added.
	 */
	public VTMatch addMatch(VTMatchInfo info);

	/**
	 * Returns a collection of all VTMatches contained in this match set.
	 * @return  a collection of all VTMatches contained in this match set.
	 */
	public Collection<VTMatch> getMatches();

	/**
	 * Returns information about the program correlator that was used to generate the matches
	 * for this match set.
	 * @return  information about the program correlator that was used to generate the matches
	 * for this match set.
	 */
	public VTProgramCorrelatorInfo getProgramCorrelatorInfo();

	/**
	 * Returns the number of matches contained in this match set.
	 * @return
	 */
	public int getMatchCount();

	/**
	 * Returns a unique id for this match set.  The ids are one-up numbers indicating the order this
	 * match set was generated in relation to other match sets in the VTSession. 
	 * @return
	 */
	public int getID();

	/**
	 * Returns a collection of all matches for the given association.
	 * @param association the association for which to search for matches.
	 * @return a collection of all matches for the given association.
	 * @see #getMatches(Address, Address, VTAssociationType)
	 */
	public Collection<VTMatch> getMatches(VTAssociation association);

	/**
	 * Returns a collection of matches for the given source and destination address.  This is
	 * equivalent to calling {@link #getMatches(VTAssociation)}.
	 * 
	 * @param sourceAddress The address in the source program for the association represented 
	 *        by the two given addresses.
	 * @param destinationAddress The address in the destination program for the association 
	 *        represented by the two given addresses.
	 * @return a collection of all matches for the association represented by the given addresses
	 * @see #getMatches(VTAssociation)
	 */
	public Collection<VTMatch> getMatches(Address sourceAddress, Address destinationAddress);

	/**
	 * Removes a match from this match set. Note that this operation is only supported for built-in
	 * match sets "Manual Matches" and "Implied Matches".
	 * @param match the match to remove.
	 * @return true if the match was removed.
	 */
	public boolean removeMatch(VTMatch match);

	/**
	 * Returns true if this match set supports removing matches.
	 * @return true if this match set supports removing matches.
	 */
	public boolean hasRemovableMatches();
}
