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
package ghidra.trace.util;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.BiConsumer;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;

public enum TraceRegisterUtils {
	;

	public static AddressRange rangeForRegister(Register register) {
		Address address = register.getAddress();
		return new AddressRangeImpl(address, address.add(register.getMinimumByteSize() - 1));
	}

	public static int byteLengthOf(Register register) {
		int bitLength = register.getBitLength();
		if ((bitLength & 7) != 0) {
			throw new IllegalArgumentException(
				"Cannot work with sub-byte boundaries. Consider using the base register.");
		}
		return bitLength >> 3;
	}

	public static byte[] padOrTruncate(byte[] arr, int length) {
		if (arr.length == length) {
			return arr;
		}
		if (arr.length < length) {
			byte[] dup = new byte[length];
			System.arraycopy(arr, 0, dup, length - arr.length, arr.length);
			return dup;
		}
		return Arrays.copyOfRange(arr, arr.length - length, arr.length);
	}

	public static ByteBuffer bufferForValue(RegisterValue value) {
		byte[] arr = value.getSignedValue().toByteArray();
		int byteLength = byteLengthOf(value.getRegister());
		arr = padOrTruncate(arr, byteLength);
		if (!value.getRegister().isBigEndian()) {
			ArrayUtils.reverse(arr);
		}
		return ByteBuffer.wrap(arr);
	}

	public static int computeMaskOffset(byte[] arr) {
		for (int i = 0; i < arr.length; i++) {
			switch (arr[i]) {
				case -1:
					return i;
				case 0:
					continue;
				default:
					throw new IllegalArgumentException(
						"Can only handle sub-registers on byte boundaries");
			}
		}
		throw new IllegalArgumentException("No value");
	}

	public static int computeMaskOffset(Register reg) {
		return computeMaskOffset(reg.getBaseMask());
	}

	public static int computeMaskOffset(RegisterValue value) {
		return computeMaskOffset(value.getRegister());
	}

	public static TraceData seekComponent(TraceData data, AddressRange range) {
		if (data == null) {
			return null;
		}
		DataType type = data.getDataType();
		if (!(type instanceof Structure)) {
			// TODO: Support dynamic structures? Probably not.
			return null;
		}
		// we know data contains register, and data cannot exceed Integer.MAX_VALUE in length
		int offset = (int) range.getMinAddress().subtract(data.getMinAddress());
		TraceData component = data.getComponentAt(offset);
		if (component == null) { // TODO: I'm not sure this can happen
			return null;
		}
		int cmpMax = range.getMaxAddress().compareTo(component.getMaxAddress());
		if (cmpMax > 0) {
			return null;
		}
		if (cmpMax == 0 && component.getMinAddress().equals(range.getMinAddress())) {
			return component;
		}
		return seekComponent(component, range);
	}

	public static TraceData seekComponent(TraceData data, Register reg) {
		return seekComponent(data, rangeForRegister(reg));
	}

	public static Object getValueHackPointer(TraceData data) {
		if (data.getValueClass() != Address.class) {
			return data.getValue();
		}
		if (!data.getAddress().getAddressSpace().isRegisterSpace()) {
			return data.getValue();
		}
		return PointerDataType.getAddressValue(data, data.getLength(),
			data.getTrace().getBaseAddressFactory().getDefaultAddressSpace());
	}

	public static String getValueRepresentationHackPointer(TraceData data) {
		if (data.getValueClass() != Address.class) {
			return data.getDefaultValueRepresentation();
		}
		Address addr = (Address) getValueHackPointer(data);
		if (addr == null) {
			return "NaP";
		}
		return addr.toString();
	}

	public static RegisterValue combineWithTraceBaseRegisterValue(RegisterValue rv, long snap,
			TraceMemoryRegisterSpace regs, boolean requireKnown) {
		Register reg = rv.getRegister();
		if (reg.isBaseRegister()) {
			return rv;
		}
		if (regs == null) {
			if (requireKnown) {
				throw new IllegalStateException("Must fetch base register before setting a child");
			}
			return rv.getBaseRegisterValue();
		}
		if (requireKnown) {
			if (TraceMemoryState.KNOWN != regs.getState(snap, reg.getBaseRegister())) {
				throw new IllegalStateException("Must fetch base register before setting a child");
			}
		}
		return regs.getValue(snap, reg.getBaseRegister()).combineValues(rv);
	}

	public static RegisterValue getRegisterValue(Register register,
			BiConsumer<Address, ByteBuffer> readAction) {
		int byteLength = TraceRegisterUtils.byteLengthOf(register);
		byte[] mask = register.getBaseMask();
		ByteBuffer buf = ByteBuffer.allocate(mask.length * 2);
		buf.put(mask);
		int maskOffset = TraceRegisterUtils.computeMaskOffset(mask);
		int startVal = buf.position() + maskOffset;
		buf.position(startVal);
		buf.limit(buf.position() + byteLength);
		readAction.accept(register.getAddress(), buf);
		byte[] arr = buf.array();
		if (!register.isBigEndian()) {
			ArrayUtils.reverse(arr, startVal, startVal + byteLength);
		}
		return new RegisterValue(register, arr);
	}
}
