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

import ghidra.program.model.address.Address;

import java.util.Collection;
import java.util.List;

/**
 * The interface for the association manager which manages the associations which are shared
 * with similar matches within a session. 
 *
 */
public interface VTAssociationManager {

	/**
	 * Returns the total number of associations that have been defined regardless of whether or
	 * not they have been accepted.
	 * @return Returns the total number of associations that have been defined regardless of whether or
	 * not they have been accepted.
	 */
	public int getAssociationCount();

	/**
	 * Returns a list of all defined associations regardless of whether or not they have been accepted.
	 * @return  a list of all defined associations regardless of whether or not they have been accepted.
	 */
	public List<VTAssociation> getAssociations();

	/**
	 * Returns an association for the given source and destination addresses if one has been defined or
	 * null if no such association has been defined.
	 * @param sourceAddress the source address for the association.
	 * @param destinationAddress the destination address for the association.
	 * @return the association if it has been defined or else null.
	 */
	public VTAssociation getAssociation(Address sourceAddress, Address destinationAddress);

	/**
	 * Returns a collection of all defined associations that have the given source address.
	 * @param sourceAddress the source address to use to search for associations.
	 * @return a collection of all defined associations that have the given source address.
	 */
	public Collection<VTAssociation> getRelatedAssociationsBySourceAddress(Address sourceAddress);

	/**
	 * Returns a collection of all defined associations that have the given destination address.
	 * @param destinaitionAddress the source address to use to search for associations.
	 * @return a collection of all defined associations that have the given destination address.
	 */
	public Collection<VTAssociation> getRelatedAssociationsByDestinationAddress(
			Address destinationAddress);

	/**
	 * Returns a collection of all defined associations that have the either the given source
	 * address or the given destination address
	 * @param sourceAddress the source address to use to search for associations.
	 * @param destinaitionAddress the source address to use to search for associations.
	 * @return a collection of all defined associations that have either the given source
	 * address or the given destination address.
	 */
	public Collection<VTAssociation> getRelatedAssociationsBySourceAndDestinationAddress(
			Address sourceAddress, Address destinationAddress);

}
