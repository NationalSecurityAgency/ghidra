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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.db.AssociationDatabaseManager;
import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.address.Address;

public class MarkupItemStorageImpl implements MarkupItemStorage {
	private final AssociationDatabaseManager associationDBM;

	private final VTAssociation association;

	private final Address sourceAddress;
	private Address destinationAddress;

	private Stringable sourceValue;
	private Stringable destinationValue;
	private String destinationAddressSource;

	private VTMarkupItemStatus status = VTMarkupItemStatus.UNAPPLIED;
	private String statusDescription = null;

	private final VTMarkupType markupType;

	public MarkupItemStorageImpl(VTAssociation association, VTMarkupType markupType,
			Address sourceAddress) {
		this(association, markupType, sourceAddress, null, null);
	}

	public MarkupItemStorageImpl(VTAssociation association, VTMarkupType markupType,
			Address sourceAddress, Address destinationAddress, String destinationAddressSource) {
		this.association = association;
		this.markupType = markupType;
		this.associationDBM = ((VTAssociationDB) association).getAssociationDatabaseManager();
		this.sourceAddress = sourceAddress;
		this.destinationAddress = destinationAddress;
		this.destinationAddressSource = destinationAddressSource;
	}

	@Override
	public VTMarkupType getMarkupType() {
		return markupType;
	}

	@Override
	public VTAssociation getAssociation() {
		return association;
	}

	@Override
	public Address getSourceAddress() {
		return sourceAddress;
	}

	@Override
	public Address getDestinationAddress() {
		return destinationAddress;
	}

	@Override
	public String getDestinationAddressSource() {
		return destinationAddressSource;
	}

	@Override
	public VTMarkupItemStatus getStatus() {
		return status;
	}

	@Override
	public String getStatusDescription() {
		return statusDescription;
	}

	public Stringable getSourceValue() {
		return sourceValue;
	}

	@Override
	public Stringable getDestinationValue() {
		return destinationValue;
	}

	@Override
	public void setSourceDestinationValues(Stringable sourceValue, Stringable destinationValue) {
		this.sourceValue = sourceValue;
		this.destinationValue = destinationValue;
	}

	@Override
	public MarkupItemStorage setStatus(VTMarkupItemStatus status) {
		this.status = status;
		return associationDBM.addMarkupItem(this);
	}

	@Override
	public MarkupItemStorage setApplyFailed(String message) {
		this.status = VTMarkupItemStatus.FAILED_APPLY;
		this.statusDescription = message;
		return associationDBM.addMarkupItem(this);
	}

	@Override
	public MarkupItemStorage reset() {
		return this;
	}

	@Override
	public MarkupItemStorage setDestinationAddress(Address destinationAddress, String addressSource) {
		this.destinationAddress = destinationAddress;
		this.destinationAddressSource = addressSource;

		if (VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE.equals(addressSource)) {
			return associationDBM.addMarkupItem(this);
		}
		return this;
	}

	@Override
	public String toString() {
		StringBuffer buffy = new StringBuffer();
		buffy.append('\n').append(getClass().getSimpleName()).append('\n');
		buffy.append('\t').append("Source Address          = ").append(sourceAddress).append('\n');
		buffy.append('\t').append("Markup Type             = ").append(markupType).append('\n');
		buffy.append('\t').append("Status                  = ").append(getStatus()).append('\n');
		buffy.append('\t').append("Status Description      = ").append(getStatusDescription()).append(
			'\n');
		buffy.append('\t').append("Source Value            = ").append(getSourceValue()).append(
			'\n');
		buffy.append('\t').append("Association             = ").append(getAssociation()).append(
			'\n');

		return buffy.toString();
	}

}
