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

import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import db.util.ErrorHandler;

/**
 * Main interface for a Version Tracking Session
 *
 */
public interface VTSession extends ErrorHandler, UndoableDomainObject {

	/**
	 * Returns the AssociationManager.
	 * @return the AssociationManager.
	 */
	public VTAssociationManager getAssociationManager();

	/**
	 * Creates a new VTMatchSet that will contain all the matches discovered by some 
	 * ProgramCorrletor algorithm run.
	 * @param correlator the VTProgramCorrelator used to generate this set of matches that will
	 * be added to this VTMatchSet.
	 * @return A new VTMatchSet that can be used to store VTMatch objects.
	 */
	public VTMatchSet createMatchSet(VTProgramCorrelator correlator);

	/**
	 * Returns a list of all VTMatchSets contained in this VTSession
	 * @return a list of all VTMatchSets contained in this VTSession
	 */
	public List<VTMatchSet> getMatchSets();

	/**
	 * Returns the source program associated with this VTSession.
	 * @return the source program associated with this VTSession.
	 */
	public Program getSourceProgram();

	/**
	 * Returns the destination program associated with this VTSession.
	 * @return the destination program associated with this VTSession.
	 */
	public Program getDestinationProgram();

	/**
	 * Returns the name of this VTSession
	 * @return the name of this VTSession
	 */
	public String getName();

	/**
	 * Saves this VTSession.
	 * @throws IOException
	 */
	public void save() throws IOException;

	/**
	 * Adds a DomainObjectListener to this VTSession.
	 * @param domainObjectListener the listener to add.
	 */
	public void addListener(DomainObjectListener domainObjectListener);

	/**
	 * Removes a DomainObjectListener from this VTSession.
	 * @param domainObjectListener the listener to remove.
	 */
	public void removeListener(DomainObjectListener domainObjectListener);

	/**
	 * Creates a new match tag with the given name.
	 * @param name the name of the new tag to create.
	 * @return the new VTMatchTag object.
	 */
	public VTMatchTag createMatchTag(String name);

	/**
	 * Deletes the given VTMatchTag from this session.
	 * @param tag the VTMatchTag to delete.
	 */
	public void deleteMatchTag(VTMatchTag tag);

	/**
	 * Returns a set of all VTMatchTags in this session.
	 * @return a set of all VTMatchTags in this session.
	 */
	public Set<VTMatchTag> getMatchTags();

	/**
	 * Returns the built-in VTMatchSet used to store manually created VTMatches.
	 * @return the built-in VTMatchSet used to store manually created VTMatches.
	 */
	public VTMatchSet getManualMatchSet();

	/**
	 * Returns the built-in VTMatchSet used to store implied VTMatches.
	 * @return the built-in VTMatchSet used to store implied VTMatches.
	 */
	public VTMatchSet getImpliedMatchSet();

	/**
	 * Returns a list of all VTMatches for the given association.
	 * @param association the VTAssociation for which to retrieve all VTMatches.
	 * @return a list of all VTMatches for the given association.
	 */
	public List<VTMatch> getMatches(VTAssociation association);

	/**
	 * Adds an Association hook that will be called whenever an association is accepted or cleared.
	 * @param hook the callback hook.
	 */
	public void addAssociationHook(AssociationHook hook);

	/**
	 * Removes the given Association hook.
	 * @param hook the callback hook to remove.
	 */
	public void removeAssociationHook(AssociationHook hook);

	public void updateSourceProgram(Program newProgram);

	public void updateDestinationProgram(Program newProgram);

}
