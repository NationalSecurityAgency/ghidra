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
package ghidra.pcode.exec;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The location of a value
 * 
 * <p>
 * This is an analog to {@link VariableStorage}, except that this records the actual storage
 * location of the evaluated variable or expression. This does not incorporate storage of
 * intermediate dereferenced values. For example, suppose {@code R0 = 0xdeadbeef}, and we want to
 * evaluate {@code *:4 R0}. The storage would be {@code ram:deadbeef:4}, not
 * {@code R0,ram:deadbeef:4}.
 */
public class ValueLocation {

	private static final AddressSpace CONST =
		new GenericAddressSpace("const", 64, AddressSpace.TYPE_CONSTANT, 0);

	public static String vnToString(Varnode vn, Language language) {
		Register register =
			language == null ? null : language.getRegister(vn.getAddress(), vn.getSize());
		if (register != null) {
			return String.format("%s:%d", register.getName(), vn.getSize());
		}
		return String.format("%s:%d", vn.getAddress(), vn.getSize());
	}

	private static boolean isZero(Varnode vn) {
		return vn.isConstant() && vn.getOffset() == 0;
	}

	private static List<Varnode> removeLeading0s(List<Varnode> nodes) {
		for (int i = 0; i < nodes.size(); i++) {
			if (!isZero(nodes.get(i))) {
				return nodes.subList(i, nodes.size());
			}
		}
		return List.of();
	}

	/**
	 * Generate the "location" of a constant
	 * 
	 * @param value the value
	 * @param size the size of the constant in bytes
	 * @return the "location"
	 */
	public static ValueLocation fromConst(long value, int size) {
		return new ValueLocation(new Varnode(CONST.getAddress(value), size));
	}

	/**
	 * Generate a location from a varnode
	 * 
	 * @param address the dynamic address of the variable
	 * @param size the size of the variable in bytes
	 * @return the location
	 */
	public static ValueLocation fromVarnode(Address address, int size) {
		return new ValueLocation(new Varnode(address, size));
	}

	private final List<Varnode> nodes;

	/**
	 * Construct a location from a list of varnodes
	 * 
	 * <p>
	 * Any leading varnodes which are constant 0s are removed.
	 * 
	 * @param nodes the varnodes
	 */
	public ValueLocation(Varnode... nodes) {
		this.nodes = removeLeading0s(List.of(nodes));
	}

	/**
	 * Construct a location from a list of varnodes
	 * 
	 * <p>
	 * Any leading varnodes which are constant 0s are removed.
	 * 
	 * @param nodes the varnodes
	 */
	public ValueLocation(List<Varnode> nodes) {
		this.nodes = removeLeading0s(List.copyOf(nodes));
	}

	/**
	 * Get the number of varnodes for this location
	 * 
	 * @return the count
	 */
	public int nodeCount() {
		return nodes.size();
	}

	/**
	 * Get the address of the first varnode
	 * 
	 * @return the address, or null if this location has no varnodes
	 */
	public Address getAddress() {
		return nodes.isEmpty() ? null : nodes.get(0).getAddress();
	}

	/**
	 * Render this location as a string, substituting registers where applicable
	 * 
	 * @param language the optional language for register substitution
	 * @return the string
	 */
	public String toString(Language language) {
		return nodes.stream().map(vn -> vnToString(vn, language)).collect(Collectors.joining(","));
	}

	@Override
	public String toString() {
		return toString(null);
	}

	/**
	 * Apply a {@link PcodeOp#INT_OR} operator
	 * 
	 * <p>
	 * There is a very restrictive set of constraints for which this yields a non-null location. If
	 * either this or that is empty, the other is returned. Otherwise, the varnodes are arranged in
	 * pairs by taking one from each storage starting at the right, or least-significant varnode.
	 * Each pair must match in length, and one of the pair must be a constant zero. The non-zero
	 * varnode is taken. The unpaired varnodes to the left, if any, are all taken. If any pair does
	 * not match in length, or if neither is zero, the resulting location is null. This logic is to
	 * ensure location information is accrued during concatenation.
	 * 
	 * @param that the other location
	 * @return the location
	 */
	public ValueLocation intOr(ValueLocation that) {
		if (this.isEmpty()) {
			return that;
		}
		if (that.isEmpty()) {
			return this;
		}
		ListIterator<Varnode> itA = this.nodes.listIterator(this.nodeCount());
		ListIterator<Varnode> itB = that.nodes.listIterator(that.nodeCount());
		Varnode[] result = new Varnode[Math.max(this.nodeCount(), that.nodeCount())];
		int i = result.length;
		while (itA.hasNext() && itB.hasPrevious()) {
			Varnode vnA = itA.previous();
			Varnode vnB = itB.previous();
			if (vnA.getSize() != vnB.getSize()) {
				return null;
			}
			if (isZero(vnA)) {
				result[--i] = vnB;
			}
			else if (isZero(vnB)) {
				result[--i] = vnA;
			}
		}
		while (itA.hasPrevious()) {
			result[--i] = itA.previous();
		}
		while (itB.hasPrevious()) {
			result[--i] = itB.previous();
		}
		return new ValueLocation(result);
	}

	/**
	 * If the location represents a constant, get its value
	 * 
	 * @return the constant value
	 */
	public BigInteger getConst() {
		BigInteger result = BigInteger.ZERO;
		for (Varnode vn : nodes) {
			if (!vn.isConstant()) {
				return null;
			}
			result = result.shiftLeft(vn.getSize() * 8);
			result = result.or(vn.getAddress().getOffsetAsBigInteger());
		}
		return result;
	}

	/**
	 * Apply a {@link PcodeOp#INT_LEFT} operator
	 * 
	 * <p>
	 * This requires the shift amount to represent an integral number of bytes. Otherwise, the
	 * result is null. This simply inserts a constant zero to the right, having the number of bytes
	 * indicated by the shift amount. This logic is to ensure location information is accrued during
	 * concatenation.
	 * 
	 * @param amount the number of bits to shift
	 * @return the location.
	 */
	public ValueLocation shiftLeft(int amount) {
		if (amount % 8 != 0) {
			return null;
		}
		List<Varnode> result = new ArrayList<>(nodes);
		result.add(new Varnode(CONST.getAddress(0), amount / 8));
		return new ValueLocation(result);
	}

	/**
	 * Get the total size of this location in bytes
	 * 
	 * @return the size in bytes
	 */
	public int size() {
		int result = 0;
		for (Varnode vn : nodes) {
			result += vn.getSize();
		}
		return result;
	}

	/**
	 * Check if this location includes any varnodes
	 * 
	 * <p>
	 * Note that a location cannot consist entirely of constant zeros and be non-empty. The
	 * constructor will have removed them all.
	 * 
	 * @return true if empty
	 */
	public boolean isEmpty() {
		return nodes.isEmpty();
	}
}
