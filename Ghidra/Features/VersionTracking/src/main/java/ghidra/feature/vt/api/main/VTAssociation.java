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

import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.Collection;

/**
 * A VTAssociation is a possible equivalence between a function or data in one program to 
 * a function or data in another program.  VTAssociations can be "Accepted" indicating that
 * the user has agreed that the association is correct.
 */
public interface VTAssociation {

	/**
	 * Returns the type of the association.  Either Function or Data.
	 * @return the type of the association.  Either Function or Data.
	 */
	public VTAssociationType getType();

	/**
	 * Returns the VTSession that this association belongs to.
	 * @return the VTSession that this association belongs to.
	 */
	public VTSession getSession();

	/**
	 * Returns a list of markup items for this association.
	 * @param monitor a task monitor used to monitor and control this operation.
	 * @return a list of markup items for this association.
	 * @throws CancelledException if the operation was cancelled via the monitor.
	 */
	public Collection<VTMarkupItem> getMarkupItems(TaskMonitor monitor) throws CancelledException;

	/**
	 * Returns true if this association is accepted and has one or more markup items that have
	 * been applied.
	 * @return true if this association is accepted and has one or more markup items that have
	 * been applied.
	 */
	public boolean hasAppliedMarkupItems();

	/**
	 * Returns the address of the function or data item in the source program for this association.
	 * @return the address of the function or data item in the source program for this association.
	 */
	public Address getSourceAddress();

	/**
	 * Returns the address of the function or data item in the source program for this association.
	 * @return the address of the function or data item in the source program for this association.
	 */
	public Address getDestinationAddress();

	/**
	 * Returns a collection of VTAssociations that have either the same source address or the same
	 * destination address. 
	 * @return  a collection of VTAssociations that have either the same source address or the same
	 * destination address.
	 */
	public Collection<VTAssociation> getRelatedAssociations();

	/**
	 * Sets the markup status of this association.  This method is used by the 
	 * {@link VTAssociationManager} to update the association with information about the state
	 * of its markup items.
	 */
	public void setMarkupStatus(VTAssociationMarkupStatus markupItemsStatus);

	/**
	 * Returns the status of the markup items for this association.  
	 * See {@link VTAssociationMarkupStatus} for details.
	 * 
	 * @return the status of the markup items for this association.
	 */
	public VTAssociationMarkupStatus getMarkupStatus();

	/**
	 * Returns the current status of this association. One of AVAILABLE, ACCEPTED, BLOCKED,
	 *  or REJECTED.  See {@link VTAssociationStatus} for details.
	 * @return  the current status of this association. One of AVAILABLE, ACCEPTED, BLOCKED, or REJECTED.
	 */
	public VTAssociationStatus getStatus();

	/**
	 * A convenience method to accept the given association without actually performing an apply.
	 * 
	 * @param association the association to accept
	 * @throws VTAssociationStatusException if the given association is 
	 *         {@link VTAssociationStatus#BLOCKED}
	 */
	public void setAccepted() throws VTAssociationStatusException;

	/**
	 * Clears the state of the given association from {@link VTAssociationStatus#ACCEPTED}
	 * or {@link VTAssociationStatus#REJECTED} to {@link VTAssociationStatus#AVAILABLE}.  
	 * This method will throw an exception if called while the given assocation's markup items 
	 * have been applied.  That is, you must first unapply any applied markup items before 
	 * calling this method. 
	 * 
	 * @param association the association whose state will be changed
	 * @throws VTAssociationStatusException if the given association's status is not 
	 *         {@link VTAssociationStatus#ACCEPTED}/{@link VTAssociationStatus#REJECTED} 
	 *         <b>or</b> if the given assocation's
	 *         {@link VTMarkupItemManager} contains markup items that have been applied. 
	 */
	public void clearStatus() throws VTAssociationStatusException;

	/**
	 * Sets the status of this association to {@link VTAssociationStatus#REJECTED}.
	 * @throws VTAssociationStatusException if the association is accepted.
	 */
	public void setRejected() throws VTAssociationStatusException;

	/**
	 * Returns the current vote count which is an application settable field which should generally
	 * be used to indicate a number of supporting facts.  For example, other accepted assocations
	 * may have matching call references to this association, each of those matching calls should
	 * have incremented the votes.  
	 * @return the current number of facts that support this association
	 */
	public int getVoteCount();

	/**
	 * Sets the vote count for this association which should be used to indicate the number of
	 * supporting facts for this association
	 * @param voteCount the new vote count for this association.
	 */
	public void setVoteCount(int voteCount);

}
