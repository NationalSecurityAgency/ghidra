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

import ghidra.program.model.address.Address;

/**
 * A VTMatch is a scoring by some algorithm that indicates a possibility that one function or data
 * item on one program matches a function or data item in another program. It consists of an 
 * association (a pairing of functions or data from one program to another) and a scoring of how
 * likely the pairing is correct. 
 *
 */

public interface VTMatch {
	public static final String BYTES_LENGTH_TYPE = "bytes";
	public static final String INSTRUCTIONS_LENGTH_TYPE = "instructions";
	public static final String AL_LINES_LENGTH_TYPE = "AL lines";

	/**
	 * returns the VTMatchSet that contains this match.
	 * @return the VTMatchSet that contains this match.
	 */
	public VTMatchSet getMatchSet();

	/**
	 * Returns the VTAssocation that this match is suggesting.
	 * @return the VTAssocation for this match.
	 */
	public VTAssociation getAssociation();

	/**
	 * Returns the tag that has been applied to this match or null if not tagged.
	 * @return the tag that has been applied to this match or null if not tagged.
	 */
	public VTMatchTag getTag();

	/**
	 * Sets the tag for this match.  Any previous tag is replaced. A value of null will remove
	 * any existing tag.
	 * @param tag the tag to set on this match.
	 */
	public void setTag(VTMatchTag tag);

	/**
	 * Returns a score that attempts to indicate how similar the associated items are to each other
	 * in a normalized score between 0 and 1.
	 * Note that short functions may have high similarity scores even though they are not really a
	 * match.
	 * @return the score that attempts to indication how similar the items are. 
	 */
	public VTScore getSimilarityScore();

	/**
	 * Returns a confidence score which is generally a combination of the similarity score and some
	 * measure of the length of the functions.  Note that this score is not normalized and all that
	 * it indicates is that higher numbers are more likely to be correct than lower numbers.  
	 * Comparing scores from different algorithms is meaningless.
	 * @return
	 */
	public VTScore getConfidenceScore();

	/**
	 * Returns the address in the source program for a match.
	 * @return the address in the source program
	 */
	public Address getSourceAddress();

	/**
	 * Returns the address in the destination program for a match.
	 * @return the address in the destination
	 */
	public Address getDestinationAddress();

	/**
	 * Returns the length of the source function or data.
	 * @return the length of the source function or data.
	 */
	public int getSourceLength();

	/**
	 * Returns the length of the destination function or data.
	 * @return the length of the destination function or data.
	 */
	public int getDestinationLength();

}
