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
package ghidra.feature.vt.gui.provider.impliedmatches;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.Collection;
import java.util.Collections;

/**
 * A class that exists to satisfy the interface of {@link VTAssociation} so that our package's 
 * mapper object can satisfy it's requirements of the {@link VTMatch} interface.
 */
class AssociationStub implements VTAssociation {

	private final Address sourceAddress;
	private final Address destinationAddress;
	private final VTAssociationType type;
	private final VTAssociationMarkupStatus markupStatus = new VTAssociationMarkupStatus();

	AssociationStub(Address sourceAddress, Address destinationAddress, VTAssociationType type) {
		this.sourceAddress = sourceAddress;
		this.destinationAddress = destinationAddress;
		this.type = type;
	}

	@Override
	public void clearStatus() throws VTAssociationStatusException {
		// no-op; dummy stub
	}

	@Override
	public Address getDestinationAddress() {
		return destinationAddress;
	}

	@Override
	public Collection<VTMarkupItem> getMarkupItems(TaskMonitor monitor) throws CancelledException {
		return Collections.emptyList();
	}

	@Override
	public VTAssociationMarkupStatus getMarkupStatus() {
		return markupStatus;
	}

	@Override
	public Collection<VTAssociation> getRelatedAssociations() {
		return Collections.emptyList();
	}

	@Override
	public VTSession getSession() {
		return null;
	}

	@Override
	public Address getSourceAddress() {
		return sourceAddress;
	}

	@Override
	public VTAssociationStatus getStatus() {
		return VTAssociationStatus.AVAILABLE;
	}

	@Override
	public VTAssociationType getType() {
		return type;
	}

	@Override
	public int getVoteCount() {
		return 0;
	}

	@Override
	public boolean hasAppliedMarkupItems() {
		return false;
	}

	@Override
	public void setAccepted() throws VTAssociationStatusException {
		// no-op; dummy stub
	}

	@Override
	public void setMarkupStatus(VTAssociationMarkupStatus markupItemsStatus) {
		// no-op; dummy stub
	}

	@Override
	public void setRejected() throws VTAssociationStatusException {
		// no-op; dummy stub
	}

	@Override
	public void setVoteCount(int voteCount) {
		// no-op; dummy stub
	}

}
