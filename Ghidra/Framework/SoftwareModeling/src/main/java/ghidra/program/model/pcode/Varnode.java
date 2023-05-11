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
import java.util.ArrayList;
import java.util.Iterator;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 *
 * Rawest possible Varnode.
 * Just a variable location and size, not part of a syntax tree.
 * A raw varnode is said to be free, it is not attached to any variable.
 */
public class Varnode {
	private static final long masks[] = { 0L, 0xffL, 0xffffL, 0xffffffL, 0xffffffffL, 0xffffffffffL,
		0xffffffffffffL, 0xffffffffffffffL, 0xffffffffffffffffL };

	private Address address;
	private int size;
	private int spaceID;
	private long offset;

	/**
	 * @param a location varnode attached to
	 * @param sz size of varnode
	 */
	public Varnode(Address a, int sz) {
		address = a;
		AddressSpace space = address.getAddressSpace();
		spaceID = space.getSpaceID();
		size = sz;
		offset = address.getOffset();
	}

	/**
	 * @param a location varnode attached to
	 * @param sz size of varnode
	 * @param symbolKey associated symbol key
	 */
	public Varnode(Address a, int sz, int symbolKey) {
		this(a, sz);
	}

	/**
	 * @return size of the varnode in bytes
	 */
	public int getSize() {
		return size;
	}

	/**
	 * @return the space this varnode belongs to (ram, register, ...)
	 */
	public int getSpace() {
		return spaceID;
	}

	/**
	 * @return the address this varnode is attached to
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Get the address where this varnode is defined or
	 * NO_ADDRESS if this varnode is an input
	 * @return the address
	 */
	public Address getPCAddress() {
		if (isInput()) {
			return Address.NO_ADDRESS;
		}
		return getDef().getSeqnum().getTarget();
	}

	/**
	 * @return the offset into the address space varnode is defined within
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the word offset into the address space this is defined within
	 * 
	 * The word size is defined in the Language's .slaspec file with the
	 * "WORDSIZE" argument when DEFINEing a memory SPACE (capitalization is
	 * for emphasis; the directives are actually lowercase).
	 * 
	 * @return the word offset into the address space this is defined within
	 */
	public long getWordOffset() {
		return address.getAddressableWordOffset();
	}

	public boolean isFree() {
		return true;
	}

	/**
	 * Determine if this varnode contains the specified address
	 * @param addr the address for which to check
	 * @return true if this varnode contains the specified address
	 */
	public boolean contains(Address addr) {
		if (spaceID != addr.getAddressSpace().getSpaceID()) {
			return false;
		}
		if (isConstant() || isUnique() || isHash()) {
			// this is not really a valid use case
			return offset == addr.getOffset();
		}
		long endOffset = offset;
		if (size > 0) {
			endOffset = offset + size - 1;
		}
		long addrOffset = addr.getOffset();
		if (offset > endOffset) { // handle long-wrap condition
			return offset <= addrOffset;
		}
		return offset <= addrOffset && endOffset >= addrOffset;
	}

	/**
	 * Determine if this varnode intersects another varnode.  
	 * @param varnode other varnode
	 * @return true if this varnode intersects the specified varnode
	 */
	public boolean intersects(Varnode varnode) {
		if (spaceID != varnode.spaceID) {
			return false;
		}
		if (isConstant() || isUnique() || isHash()) {
			// this is not really a valid use case
			return offset == varnode.getOffset();
		}
		long endOtherOffset = varnode.offset;
		if (varnode.size > 0) {
			endOtherOffset = varnode.offset + varnode.size - 1;
		}
		return rangeIntersects(varnode.offset, endOtherOffset);
	}

	private boolean rangeIntersects(long otherOffset, long otherEndOffset) {
		long endOffset = offset;
		if (size > 0) {
			endOffset = offset + size - 1;
		}
		if (offset > endOffset) { // handle long-wrap condition
			if (otherOffset > otherEndOffset) {
				return true; // both wrapped - must intersect
			}
			return offset <= otherEndOffset;
		}
		if (otherOffset > otherEndOffset) { // handle wrap condition
			return endOffset >= otherOffset;
		}
		return offset <= otherEndOffset && endOffset >= otherOffset;
	}

	/**
	 * Determine if this varnode intersects the specified address set
	 * @param set address set
	 * @return true if this varnode intersects the specified address set
	 */
	public boolean intersects(AddressSetView set) {
		if (isConstant() || isUnique() || isHash() || set == null || set.isEmpty()) {
			return false;
		}
		for (AddressRange range : set.getAddressRanges()) {
			Address minAddr = range.getMinAddress();
			if (minAddr.getAddressSpace().getSpaceID() != spaceID) {
				continue;
			}
			Address maxAddr = range.getMaxAddress();
			if (rangeIntersects(minAddr.getOffset(), maxAddr.getOffset())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return true if this varnode exists in a Memory space (vs. register etc...).
	 * Keep in mind this varnode may also correspond to a defined register 
	 * if true is returned and {@link #isRegister()} return false.  
	 * Memory-based registers may be indirectly addressed which leads to the 
	 * distinction with registers within the register space.
	 */
	public boolean isAddress() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return type == AddressSpace.TYPE_RAM;
	}

	/**
	 * @return true if this varnode exists in a Register type space.
	 * If false is returned, keep in mind this varnode may still correspond to a 
	 * defined register within a memory space.  Memory-based registers may be indirectly 
	 * addressed which leads to the distinction with registers within the register space.
	 */
	public boolean isRegister() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_REGISTER);
	}

	/**
	 * @return true if this varnode is just a constant number
	 */
	public boolean isConstant() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_CONSTANT);
	}

	/**
	 * @return true if this varnode doesn't exist anywhere.  A temporary variable.
	 */
	public boolean isUnique() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_UNIQUE);
	}

	public boolean isHash() {
		return spaceID == AddressSpace.HASH_SPACE.getSpaceID();
	}

	/**
	 * @return is input to a pcode op
	 */
	public boolean isInput() {
		return false;				// Not a valid query with a free varnode
	}

	/**
	 * @return is persistent
	 */
	public boolean isPersistent() {
		return false;				// Not a valid query with a free varnode
	}

	/**
	 * @return is mapped to an address
	 */
	public boolean isAddrTied() {
		return false;				// Not a valid query with a free varnode
	}

	public boolean isUnaffected() {
		return false;				// Not a valid query with a free varnode
	}

	/**
	 * @return get the pcode op this varnode belongs to
	 */
	public PcodeOp getDef() {
		return null;					// Not a valid query with a free varnode
	}

	/**
	 * @return iterator to all PcodeOp s that take this as input
	 */
	public Iterator<PcodeOp> getDescendants() {
		return null;					// Not a valid query with a free varnode
	}

	/**
	 * If there is only one PcodeOp taking this varnode as input, return it. Otherwise return null
	 * @return the lone descendant PcodeOp
	 */
	public PcodeOp getLoneDescend() {
		return null;
	}

	/**
	 * @return the high level variable this varnode represents
	 */
	public HighVariable getHigh() {
		return null;
	}

	/**
	 * @return the index of the group, within the high containing this, that are forced merged with this  
	 */
	public short getMergeGroup() {
		return 0;
	}

	/**
	 * Encode just the raw storage info for this Varnode to stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodeRaw(Encoder encoder) throws IOException {
		AddressXML.encode(encoder, address, size);
	}

	/**
	 * Encode details of the Varnode as a formatted string with three colon separated fields.
	 *   space:offset:size
	 * The name of the address space, the offset of the address as a hex number, and
	 * the size field as a decimal number.
	 * @return the formatted String
	 */
	public String encodePiece() {
		StringBuilder buffer = new StringBuilder();
		Address addr = address;
		AddressSpace space = addr.getAddressSpace();
		buffer.append(space.getName());
		buffer.append(":0x");
		long off = addr.getUnsignedOffset();
		buffer.append(Long.toHexString(off));
		buffer.append(':');
		buffer.append(Integer.toString(size));
		return buffer.toString();
	}

	/**
	 * Decode a Varnode from a stream
	 * 
	 * @param decoder is the stream decoder
	 * @param factory pcode factory used to create valid pcode
	 * @return the new Varnode
	 * @throws DecoderException if the Varnode is improperly encoded
	 */
	public static Varnode decode(Decoder decoder, PcodeFactory factory) throws DecoderException {
		int el = decoder.peekElement();
		if (el == ELEM_VOID.id()) {
			decoder.openElement();
			decoder.closeElement(el);
			return null;
		}
		else if (el == ELEM_SPACEID.id() || el == ELEM_IOP.id()) {
			Address addr = AddressXML.decode(decoder);
			return factory.newVarnode(4, addr);
		}

		el = decoder.openElement();
		int ref = -1;
		int sz = 4;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			else if (attribId == ATTRIB_REF.id()) {	// If we have a reference
				ref = (int) decoder.readUnsignedInteger();
				Varnode vn = factory.getRef(ref);				// The varnode may already exist
				if (vn != null) {
					decoder.closeElement(el);
					return vn;
				}
			}
			else if (attribId == ATTRIB_SIZE.id()) {
				sz = (int) decoder.readSignedInteger();
			}
		}
		decoder.rewindAttributes();
		Varnode vn;
		Address addr = AddressXML.decodeFromAttributes(decoder);
		AddressSpace spc = addr.getAddressSpace();
		if ((spc != null) && (spc.getType() == AddressSpace.TYPE_VARIABLE)) {	// Check for a composite Address
			decoder.rewindAttributes();
			try {
				Varnode[] pieces = decodePieces(decoder);
				VariableStorage storage = factory.getJoinStorage(pieces);
				// Update "join" address to the one just registered with the pieces
				addr = factory.getJoinAddress(storage);
			}
			catch (InvalidInputException e) {
				throw new DecoderException("Invalid varnode pieces: " + e.getMessage());
			}
		}
		if (ref != -1) {
			vn = factory.newVarnode(sz, addr, ref);
		}
		else {
			vn = factory.newVarnode(sz, addr);
		}
		decoder.rewindAttributes();
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			else if (attribId == ATTRIB_GRP.id()) {
				short val = (short) decoder.readSignedInteger();
				factory.setMergeGroup(vn, val);
			}
			else if (attribId == ATTRIB_PERSISTS.id()) {
				if (decoder.readBool()) {
					factory.setPersistent(vn, true);
				}
			}
			else if (attribId == ATTRIB_ADDRTIED.id()) {
				if (decoder.readBool()) {
					factory.setAddrTied(vn, true);
				}
			}
			else if (attribId == ATTRIB_UNAFF.id()) {
				if (decoder.readBool()) {
					factory.setUnaffected(vn, true);
				}
			}
			else if (attribId == ATTRIB_INPUT.id()) {
				if (decoder.readBool()) {
					vn = factory.setInput(vn, true);
				}
			}
			else if (attribId == ATTRIB_VOLATILE.id()) {
				if (decoder.readBool()) {
					factory.setVolatile(vn, true);
				}
			}
		}
		decoder.closeElement(el);
		return vn;
	}

	/**
	 * Decode a Varnode from a description in a string.
	 * The format should be three colon separated fields:  space:offset:size
	 * The space field should be the name of an address space, the offset field should
	 * be a hexadecimal number, and the size field should be a decimal number.
	 * @param pieceStr is the formatted string
	 * @param addrFactory is the factory used to look up the address space
	 * @return a new Varnode as described by the string
	 * @throws DecoderException if the string is improperly formatted
	 */
	private static Varnode decodePiece(String pieceStr, AddressFactory addrFactory)
			throws DecoderException {
// TODO: Can't handle register name since addrFactory can't handle this
		String[] varnodeTokens = pieceStr.split(":");
		if (varnodeTokens.length != 3) {
			throw new DecoderException("Invalid \"join\" address piece: " + pieceStr);
		}
		AddressSpace space = addrFactory.getAddressSpace(varnodeTokens[0]);
		if (space == null) {
			throw new DecoderException("Invalid space for \"join\" address piece: " + pieceStr);
		}
		if (!varnodeTokens[1].startsWith("0x")) {
			throw new DecoderException("Invalid offset for \"join\" address piece: " + pieceStr);
		}
		long offset;
		try {
			offset = Long.parseUnsignedLong(varnodeTokens[1].substring(2), 16);
		}
		catch (NumberFormatException e) {
			throw new DecoderException("Invalid offset for \"join\" address piece: " + pieceStr);
		}
		int size;
		try {
			size = Integer.parseInt(varnodeTokens[2]);
		}
		catch (NumberFormatException e) {
			throw new DecoderException("Invalid size for \"join\" address piece: " + pieceStr);
		}
		return new Varnode(space.getAddress(offset), size);
	}

	/**
	 * Decode a sequence of Varnodes from "piece" attributes for the current open element.
	 * The Varnodes are normally associated with an Address in the "join" space. In this virtual
	 * space, a contiguous sequence of bytes, at a specific Address, represent a logical value
	 * that may physically be split across multiple registers or other storage locations.
	 * @param decoder is the stream decoder
	 * @return an array of decoded Varnodes
	 * @throws DecoderException for any errors in the encoding
	 */
	public static Varnode[] decodePieces(Decoder decoder) throws DecoderException {
		ArrayList<Varnode> list = new ArrayList<>();
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			else if (attribId == ATTRIB_UNKNOWN.id()) {
				attribId = decoder.getIndexedAttributeId(ATTRIB_PIECE);
			}

			if (attribId >= ATTRIB_PIECE.id()) {
				int index = attribId - ATTRIB_PIECE.id();
				if (index > AddressXML.MAX_PIECES) {
					continue;
				}
				if (index != list.size()) {
					throw new DecoderException("\"piece\" attributes must be in order");
				}
				list.add(decodePiece(decoder.readString(), decoder.getAddressFactory()));
			}
		}
		Varnode[] pieces = new Varnode[list.size()];
		list.toArray(pieces);
		return pieces;
	}

	/**
	 * Trim a varnode in a constant space to the correct starting offset.
	 * 
	 * Constant handles may contain constants of indeterminate size.
	 * This is where the size gets fixed, i.e. we mask off the constant
	 * to its proper size.  A varnode that is ends up in pcode should
	 * call this method to ensure that varnodes always contains raw data.
	 * On the other hand, varnodes in handles are allowed to have offsets
	 * that violate size restrictions.
	 */
	public void trim() {
		if (address.getAddressSpace().getType() == AddressSpace.TYPE_CONSTANT) {
			offset = offset & masks[size];
			address = address.getNewAddress(offset);
		}
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return ("(" + address.getAddressSpace().getName() + ", 0x" + Long.toHexString(offset) +
			", " + size + ")");
	}

	/**
	 * Convert this varnode to an alternate String representation based on a specified language.
	 * @param language is the specified Language
	 * @return string representation
	 */
	public String toString(Language language) {
		if (isAddress() || isRegister()) {
			Register reg = language.getRegister(address, size);
			if (reg != null) {
				return reg.getName();
			}
		}
		if (isUnique()) {
			return "u_" + Long.toHexString(offset) + ":" + size;
		}
		if (isConstant()) {
			return "0x" + Long.toHexString(offset);
		}
		return "A_" + address + ":" + size;
	}

	@Override
	public boolean equals(Object o) {
		//
		// Note: it is not clear if the equals/hashCode currently work correctly when used in 
		//       OverlayAddressSpaces.  There is a ticket to examine this issue.
		//

		if (o == this) {
			return true;
		}
		if (!(o instanceof Varnode)) {
			return false;
		}

		Varnode vn = (Varnode) o;
		if (!vn.isFree()) {
			return false;
		}

		return (this.offset == vn.getOffset() && this.size == vn.getSize() &&
			this.spaceID == vn.getSpace());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (offset ^ (offset >>> 32));
		result = prime * result + size;
		result = prime * result + spaceID;
		return result;
	}
}
