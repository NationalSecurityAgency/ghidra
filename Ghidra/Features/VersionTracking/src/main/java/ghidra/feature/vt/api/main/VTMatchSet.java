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
package ghidra.feature.vt.api.main;

import java.util.Collection;

import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.program.model.address.Address;

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
	 * @return the number of matches contained in this match set.
	 */
	public int getMatchCount();

	/**
	 * Returns a unique id for this match set.  The ids are one-up numbers indicating the order this
	 * match set was generated in relation to other match sets in the VTSession. 
	 * @return the id
	 */
	public int getID();

	/**
	 * Returns a collection of all matches for the given association.
	 * @param association the association for which to search for matches.
	 * @return a collection of all matches for the given association.
	 * @see #getMatches(Address, Address)
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
	 * Deletes the given match from this match set.  
	 * <P>
	 * Note: deleting an <B>ACCEPTED</B> match removes potentially useful corroborating evidence 
	 * from future correlation. Before deleting a match, consider instead filtering matches out of
	 * the UI that you are finished applying.  
	 * <P>
	 * If this is the last match that shares the match's association, then the association will also
	 * be removed, along with any markup items in the database.  <B>Any applied markup item data 
	 * will not be changed.</B>  
	 * 
	 * @param match the match
	 */
	public void deleteMatch(VTMatch match);

	/**
	 * Removes a match from this match set.
	 * <P>
	 * If this is the last match that shares the match's association, then the match will only be
	 * removed if the association is not accepted.   In that case, no remove will take place and 
	 * this method will return false. 
	 * <P>
	 * Note:  This method is deprecated.  It unfortunately shares a very similar name with its 
	 * replacement, {@link #deleteMatch(VTMatch)}.   The replacement method will delete the match 
	 * and the related association and markup items in the database, if the match is the last match
	 * to use that association.  This deprecated method does not remove the remaining association or
	 * markup items.   Historically, this method has been called after clearing the given match and
	 * its markup. Once this method has been deleted, clients will be responsible for managing the
	 * markup item state before calling {@link #deleteMatch(VTMatch)}.
	 * 
	 * @param match the match to remove.
	 * @return true if the match was removed.
	 * @throws IllegalArgumentException if a non-database match is passed to this method
	 * @see #deleteMatch(VTMatch)
	 * @deprecated use {@link #deleteMatch(VTMatch)} 
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	public boolean removeMatch(VTMatch match);

	/**
	 * Returns true 
	 * @return true
	 * @deprecated this method now always returns true
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	public default boolean hasRemovableMatches() {
		return true;
	}
}
