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
package ghidra.program.model.pcode;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * An ephemeral unsigned value-domain contract for one LOAD result in one invocation context.
 * The producer must establish the type-to-value binding in the current decompilation context.
 * Provenance is audit information, not proof that the contract applies to a particular SSA value.
 * Consumers must independently match the LOAD and, if present, its required control-flow edge.
 * This record neither changes a datatype nor persists an assumption in the program database.
 */
public final class ValueDomainConstraint {
	private final Address ownerEntry;
	private final Address loadAddress;
	private final int outputSize;
	private final Address switchAddress;
	private final long first;
	private final long last;
	private final Address descriptorAddress;
	private final String provenance;
	private final Address guardAddress;
	private final boolean guardTrue;

	/**
	 * Construct a LOAD-wide contract in the explicit invocation context, with inclusive unsigned
	 * bounds. Consumers may follow the matched SSA result to any use, but must still establish
	 * the owner and LOAD identity. This does not narrow unknown callers of the function.
	 */
	public ValueDomainConstraint(Address ownerEntry, Address loadAddress, int outputSize,
			long first, long last, Address descriptorAddress, String provenance) {
		this(ownerEntry, loadAddress, outputSize, Address.NO_ADDRESS, first, last,
			descriptorAddress, provenance, null, false, false);
	}

	/** Construct a LOAD-wide contract restricted to the required CBRANCH edge, if supplied. */
	public ValueDomainConstraint(Address ownerEntry, Address loadAddress, int outputSize,
			long first, long last, Address descriptorAddress, String provenance,
			Address guardAddress, boolean guardTrue) {
		this(ownerEntry, loadAddress, outputSize, Address.NO_ADDRESS, first, last,
			descriptorAddress, provenance, guardAddress, guardTrue, false);
	}

	/**
	 * Construct an unconditional contract, with inclusive unsigned bounds.
	 */
	public ValueDomainConstraint(Address ownerEntry, Address loadAddress, int outputSize,
			Address switchAddress, long first, long last, Address descriptorAddress,
			String provenance) {
		this(ownerEntry, loadAddress, outputSize, switchAddress, first, last,
			descriptorAddress, provenance, null, false);
	}

	/**
	 * Construct a contract optionally restricted to a CBRANCH edge. A null guard means no edge
	 * restriction; otherwise {@code guardTrue} identifies the required outcome of the original raw
	 * p-code CBRANCH condition, before native optimization changes its sense.
	 * @throws IllegalArgumentException if a bound, size, address, or provenance is invalid
	 */
	public ValueDomainConstraint(Address ownerEntry, Address loadAddress, int outputSize,
			Address switchAddress, long first, long last, Address descriptorAddress,
			String provenance, Address guardAddress, boolean guardTrue) {
		this(ownerEntry, loadAddress, outputSize, switchAddress, first, last,
			descriptorAddress, provenance, guardAddress, guardTrue, true);
	}

	private ValueDomainConstraint(Address ownerEntry, Address loadAddress, int outputSize,
			Address switchAddress, long first, long last, Address descriptorAddress,
			String provenance, Address guardAddress, boolean guardTrue, boolean useRestricted) {
		this.ownerEntry = requireAddress(ownerEntry);
		this.loadAddress = requireAddress(loadAddress);
		this.switchAddress = useRestricted ? requireAddress(switchAddress) : Address.NO_ADDRESS;
		this.descriptorAddress = requireAddress(descriptorAddress);
		if (outputSize < 1 || outputSize > 8) {
			throw new IllegalArgumentException("Value-domain width must be 1 through 8 bytes");
		}
		long maximum = outputSize == 8 ? -1L : (1L << (8 * outputSize)) - 1;
		if (Long.compareUnsigned(first, last) > 0 ||
			Long.compareUnsigned(last, maximum) > 0) {
			throw new IllegalArgumentException("Value-domain bounds do not fit the unsigned width");
		}
		this.provenance = Objects.requireNonNull(provenance);
		if (provenance.isBlank()) {
			throw new IllegalArgumentException("Value-domain provenance is required");
		}
		this.outputSize = outputSize;
		this.first = first;
		this.last = last;
		this.guardAddress = guardAddress == null ? null : requireAddress(guardAddress);
		this.guardTrue = guardAddress != null && guardTrue;
	}

	private static Address requireAddress(Address address) {
		if (address == null || !address.isMemoryAddress()) {
			throw new IllegalArgumentException("Value-domain addresses must be memory addresses");
		}
		return address;
	}

	public Address getOwnerEntry() { return ownerEntry; }
	public Address getLoadAddress() { return loadAddress; }
	public int getOutputSize() { return outputSize; }
	public Address getSwitchAddress() { return switchAddress; }
	public boolean isUseRestricted() { return switchAddress != Address.NO_ADDRESS; }
	public long getFirst() { return first; }
	public long getLast() { return last; }
	public Address getDescriptorAddress() { return descriptorAddress; }
	public String getProvenance() { return provenance; }
	public Address getGuardAddress() { return guardAddress; }
	public boolean isGuardTrue() { return guardTrue; }

	/**
	 * Test whether two contracts address overlapping result/use selectors. LOAD-wide and exact-use
	 * contracts for the same LOAD overlap. Even different guards do not
	 * make duplicate selectors safe: callers must resolve competing evidence before sending it.
	 */
	public boolean hasSameSelector(ValueDomainConstraint other) {
		return ownerEntry.equals(other.ownerEntry) && loadAddress.equals(other.loadAddress) &&
			outputSize == other.outputSize && (!isUseRestricted() || !other.isUseRestricted() ||
			switchAddress.equals(other.switchAddress));
	}

	/**
	 * Encode schema 1. The ordered address roles are owner, load, switch, descriptor, then guard
	 * if present. The switch child has no space/offset for a LOAD-wide contract. The index is -1
	 * for no guard, 0 for its false edge, and 1 for its true edge.
	 */
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VALUEDOMAIN);
		encoder.writeSignedInteger(ATTRIB_FORMAT, 1);
		encoder.writeString(ATTRIB_TYPE, "load");
		encoder.writeSignedInteger(ATTRIB_SIZE, outputSize);
		encoder.writeUnsignedInteger(ATTRIB_FIRST, first);
		encoder.writeUnsignedInteger(ATTRIB_LAST, last);
		encoder.writeString(ATTRIB_NAME, provenance);
		encoder.writeSignedInteger(ATTRIB_INDEX, guardAddress == null ? -1 : guardTrue ? 1 : 0);
		encodeAddress(encoder, "owner", ownerEntry);
		encodeAddress(encoder, "load", loadAddress);
		encodeAddress(encoder, "switch", switchAddress);
		encodeAddress(encoder, "descriptor", descriptorAddress);
		if (guardAddress != null) {
			encodeAddress(encoder, "guard", guardAddress);
		}
		encoder.closeElement(ELEM_VALUEDOMAIN);
	}

	private static void encodeAddress(Encoder encoder, String role, Address address)
			throws IOException {
		encoder.openElement(ELEM_ADDR);
		encoder.writeString(ATTRIB_TYPE, role);
		if (address != Address.NO_ADDRESS) {
			AddressXML.encodeAttributes(encoder, address);
		}
		encoder.closeElement(ELEM_ADDR);
	}

	/** Decode a schema-1 contract, rejecting unsupported or malformed records. */
	public static ValueDomainConstraint decode(Decoder decoder) throws DecoderException {
		int element = decoder.openElement(ELEM_VALUEDOMAIN);
		int fields = 0;
		long format = -1, size = 0, first = 0, last = 0, edge = -2;
		String type = null, provenance = null;
		for (int id; (id = decoder.getNextAttributeId()) != 0;) {
			int bit;
			if (id == ATTRIB_FORMAT.id()) { bit = 1; format = decoder.readSignedInteger(); }
			else if (id == ATTRIB_TYPE.id()) { bit = 2; type = decoder.readString(); }
			else if (id == ATTRIB_SIZE.id()) { bit = 4; size = decoder.readSignedInteger(); }
			else if (id == ATTRIB_FIRST.id()) { bit = 8; first = decoder.readUnsignedInteger(); }
			else if (id == ATTRIB_LAST.id()) { bit = 16; last = decoder.readUnsignedInteger(); }
			else if (id == ATTRIB_NAME.id()) { bit = 32; provenance = decoder.readString(); }
			else if (id == ATTRIB_INDEX.id()) { bit = 64; edge = decoder.readSignedInteger(); }
			else { throw new DecoderException("Unknown value-domain attribute"); }
			if ((fields & bit) != 0) {
				throw new DecoderException("Duplicate value-domain attribute");
			}
			fields |= bit;
		}
		if (fields != 127 || format != 1 || !"load".equals(type) ||
			size < 1 || size > 8 || edge < -1 || edge > 1) {
			throw new DecoderException("Unsupported value-domain schema");
		}
		Address owner = decodeAddress(decoder, "owner");
		Address load = decodeAddress(decoder, "load");
		Address use = decodeAddress(decoder, "switch");
		Address descriptor = decodeAddress(decoder, "descriptor");
		Address guard = edge == -1 ? null : decodeAddress(decoder, "guard");
		decoder.closeElement(element);
		try {
			if (use == Address.NO_ADDRESS) {
				return new ValueDomainConstraint(owner, load, (int) size, first, last,
					descriptor, provenance, guard, edge == 1);
			}
			return new ValueDomainConstraint(owner, load, (int) size, use, first, last,
				descriptor, provenance, guard, edge == 1);
		}
		catch (IllegalArgumentException e) {
			throw new DecoderException(e.getMessage());
		}
	}

	private static Address decodeAddress(Decoder decoder, String role) throws DecoderException {
		int element = decoder.openElement(ELEM_ADDR);
		int fields = 0;
		String actualRole = null;
		AddressSpace space = null;
		long offset = 0;
		for (int id; (id = decoder.getNextAttributeId()) != 0;) {
			int bit;
			if (id == ATTRIB_TYPE.id()) { bit = 1; actualRole = decoder.readString(); }
			else if (id == ATTRIB_SPACE.id()) { bit = 2; space = decoder.readSpace(); }
			else if (id == ATTRIB_OFFSET.id()) { bit = 4; offset = decoder.readUnsignedInteger(); }
			else { throw new DecoderException("Unknown value-domain address attribute"); }
			if ((fields & bit) != 0) {
				throw new DecoderException("Duplicate value-domain address attribute");
			}
			fields |= bit;
		}
		if (fields == 1 && "switch".equals(role) && role.equals(actualRole)) {
			decoder.closeElement(element);
			return Address.NO_ADDRESS;
		}
		if (fields != 7 || !role.equals(actualRole) || space == null) {
			throw new DecoderException("Unexpected value-domain address role");
		}
		decoder.closeElement(element);
		Address address;
		try {
			address = space.getAddress(offset);
		}
		catch (IllegalArgumentException e) {
			throw new DecoderException(e.getMessage());
		}
		return address;
	}
}
