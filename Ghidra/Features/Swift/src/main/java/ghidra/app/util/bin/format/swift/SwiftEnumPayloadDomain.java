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
package ghidra.app.util.bin.format.swift;

import java.util.List;

import ghidra.program.model.address.Address;

/**
 * A proven one-byte encoding of a selected no-payload enum stored in an enum payload.
 * This layout proof does not bind arbitrary data or a function input to the type.
 */
public final class SwiftEnumPayloadDomain {
	private final Address metadataAddress;
	private final Address descriptorAddress;
	private final Address payloadDescriptorAddress;
	private final int payloadOrdinal;
	private final int encodedFirst;
	private final int encodedLast;
	private final List<Address> witnesses;
	private final String evidenceSha256;

	SwiftEnumPayloadDomain(Address metadataAddress, Address descriptorAddress,
			Address payloadDescriptorAddress, int payloadOrdinal, int encodedFirst, int encodedLast,
			List<Address> witnesses, String evidenceSha256) {
		this.metadataAddress = metadataAddress;
		this.descriptorAddress = descriptorAddress;
		this.payloadDescriptorAddress = payloadDescriptorAddress;
		this.payloadOrdinal = payloadOrdinal;
		this.encodedFirst = encodedFirst;
		this.encodedLast = encodedLast;
		this.witnesses = List.copyOf(witnesses);
		this.evidenceSha256 = evidenceSha256;
	}

	/** {@return the exact parent enum metadata identity} */
	public Address getMetadataAddress() {
		return metadataAddress;
	}
	/** {@return the exact parent enum descriptor identity} */
	public Address getDescriptorAddress() {
		return descriptorAddress;
	}
	/** {@return the exact selected payload descriptor identity} */
	public Address getPayloadDescriptorAddress() {
		return payloadDescriptorAddress;
	}
	/** {@return the selected declaration-order payload case} */
	public int getPayloadOrdinal() {
		return payloadOrdinal;
	}
	/** {@return the first legal stored byte of this selected payload} */
	public int getEncodedFirst() {
		return encodedFirst;
	}
	/** {@return the last legal stored byte of this selected payload} */
	public int getEncodedLast() {
		return encodedLast;
	}
	/** {@return the one-byte storage size proved by the value witnesses} */
	public int getStorageSize() {
		return 1;
	}
	/** {@return immutable get-tag, project, and inject witness addresses in ABI order} */
	public List<Address> getWitnessAddresses() {
		return witnesses;
	}
	/** {@return SHA256 of metadata, typeref, loaded-pointer, and instruction byte evidence} */
	public String getEvidenceSha256() {
		return evidenceSha256;
	}
	/**
	 * @param value a candidate stored byte
	 * @return whether the byte is in the proven selected-payload domain
	 */
	public boolean containsEncodedValue(int value) {
		return value >= encodedFirst && value <= encodedLast;
	}
}
