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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.OverlappingObjectIterator.Ranger;

public enum TraceRegisterUtils {
	;

	private static class RegisterIndex {
		// Could this all go into RegisterManager instead?
		// Would need the overlapping object iterator, or replacement, moved up
		private record RegEntry(AddressRange base, Set<Register> regs) {}

		private static final Ranger<RegEntry> ENTRY_RANGER = new Ranger<>() {
			@Override
			public Address getMinAddress(RegEntry t) {
				return t.base.getMinAddress();
			}

			@Override
			public Address getMaxAddress(RegEntry t) {
				return t.base.getMaxAddress();
			}
		};
		private NavigableMap<Address, RegEntry> map = new TreeMap<>();

		private RegisterIndex(Language language) {
			for (Register reg : language.getRegisters()) {
				RegEntry re = map.computeIfAbsent(reg.getAddress(),
					k -> new RegEntry(rangeForRegister(reg.getBaseRegister()), new HashSet<>()));
				re.regs.add(reg);
			}
		}

		private Set<Register> findIntersecting(AddressSetView set) {
			AddressSet inBaseSpace = new AddressSet();
			for (AddressRange rng : set) {
				if (rng.getAddressSpace().isOverlaySpace()) {
					inBaseSpace.add(rng.getMinAddress().getPhysicalAddress(),
						rng.getMaxAddress().getPhysicalAddress());
				}
				else {
					inBaseSpace.add(rng);
				}
			}
			Set<Register> result = new HashSet<>();
			OverlappingObjectIterator<AddressRange, RegEntry> ooit =
				new OverlappingObjectIterator<>(
					inBaseSpace.iterator(), OverlappingObjectIterator.ADDRESS_RANGE,
					map.subMap(inBaseSpace.getMinAddress(), true,
						inBaseSpace.getMaxAddress(), true).values().iterator(),
					ENTRY_RANGER);
			while (ooit.hasNext()) {
				Pair<AddressRange, RegEntry> next = ooit.next();
				for (Register reg : next.getRight().regs) {
					if (rangeForRegister(reg).intersects(next.getLeft())) {
						result.add(reg);
					}
				}
			}
			return result;
		}
	}

	private static final Map<Language, RegisterIndex> REGISTER_INDICES = new WeakHashMap<>();

	public static Set<Register> registersIntersecting(Language language, AddressSetView set) {
		return REGISTER_INDICES.computeIfAbsent(language, RegisterIndex::new).findIntersecting(set);
	}

	public static AddressRange rangeForRegister(Register register) {
		Address address = register.getAddress();
		return new AddressRangeImpl(address, address.add(register.getNumBytes() - 1));
	}

	public static AddressRange getOverlayRange(AddressSpace space, AddressRange range) {
		AddressSpace physical = space.getPhysicalSpace();
		if (physical == space || physical != range.getAddressSpace()) {
			return range;
		}
		return new AddressRangeImpl(
			space.getAddress(range.getMinAddress().getOffset()),
			space.getAddress(range.getMaxAddress().getOffset()));
	}

	public static AddressSetView getOverlaySet(AddressSpace space, AddressSetView set) {
		if (!space.isOverlaySpace()) {
			return set;
		}
		AddressSet result = new AddressSet();
		for (AddressRange rng : set) {
			result.add(getOverlayRange(space, rng));
		}
		return result;
	}

	public static AddressRange getPhysicalRange(AddressRange range) {
		AddressSpace space = range.getAddressSpace();
		AddressSpace physical = space.getPhysicalSpace();
		if (space == physical) {
			return range;
		}
		return new AddressRangeImpl(
			physical.getAddress(range.getMinAddress().getOffset()),
			physical.getAddress(range.getMaxAddress().getOffset()));
	}

	/**
	 * Convert a set in an overlay space to the corresponding set in its physical space
	 * 
	 * @param set a set contained entirely in one space
	 * @return the physical set
	 */
	public static AddressSetView getPhysicalSet(AddressSetView set) {
		if (set.isEmpty() || !set.getMinAddress().getAddressSpace().isOverlaySpace()) {
			return set;
		}
		AddressSet result = new AddressSet();
		for (AddressRange rng : set) {
			result.add(getPhysicalRange(rng));
		}
		return result;
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

	public static ByteBuffer bufferForValue(Register register, RegisterValue value) {
		byte[] bytes = value.toBytes().clone();
		int start = bytes.length / 2;
		// NB: I guess contextreg is always big?
		if (!register.isBigEndian() && !register.isProcessorContext()) {
			ArrayUtils.reverse(bytes, start, bytes.length);
		}
		int offset = TraceRegisterUtils.computeMaskOffset(register);
		return ByteBuffer.wrap(bytes, start + offset, register.getNumBytes());
	}

	public static int computeMaskOffset(Register reg) {
		if (reg.isBaseRegister()) {
			return 0;
		}
		return reg.getOffset() - reg.getBaseRegister().getOffset();
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

	public static RegisterValue encodeValueRepresentationHackPointer(Register register,
			TraceData data, String representation) throws DataTypeEncodeException {
		DataType dataType = data.getBaseDataType();
		if (data.getValueClass() != Address.class) {
			byte[] bytes =
				dataType.encodeRepresentation(representation, data, data, data.getLength());
			BigInteger value = Utils.bytesToBigInteger(bytes, register.getMinimumByteSize(),
				register.isBigEndian(), false);
			return new RegisterValue(register, value);
		}
		Address addr = data.getTrace().getBaseAddressFactory().getAddress(representation);
		if (addr == null) {
			throw new DataTypeEncodeException("Invalid address", representation, dataType);
		}
		return new RegisterValue(register, addr.getOffsetAsBigInteger());
	}

	public static RegisterValue combineWithTraceParentRegisterValue(Register parent,
			RegisterValue rv, TracePlatform platform, long snap, TraceMemorySpace regs,
			boolean requireKnown) {
		Register reg = rv.getRegister();
		if (reg == parent) {
			return rv;
		}
		if (regs == null) {
			if (requireKnown) {
				throw new IllegalStateException("Must fetch " + parent + " before setting " + reg);
			}
			return rv.getRegisterValue(parent);
		}
		if (requireKnown) {
			if (TraceMemoryState.KNOWN != regs.getState(platform, snap, parent)) {
				throw new IllegalStateException("Must fetch " + parent + " before setting " + reg);
			}
		}
		return regs.getValue(platform, snap, parent).combineValues(rv);
	}

	public static RegisterValue combineWithTraceBaseRegisterValue(RegisterValue rv,
			TracePlatform platform, long snap, TraceMemorySpace regs, boolean requireKnown) {
		return combineWithTraceParentRegisterValue(rv.getRegister().getBaseRegister(), rv, platform,
			snap, regs, requireKnown);
	}

	public static ByteBuffer prepareBuffer(Register register) {
		/*
		 * The byte array for reg values spans the whole base register, but we'd like to avoid
		 * over-reading, so we'll zero in on the bytes actually included in the mask. We'll then
		 * have to handle endianness and such. The regval instance should then apply the actual mask
		 * for the sub-register, if applicable.
		 */
		int byteLength = register.getNumBytes();
		byte[] mask = register.getBaseMask();
		ByteBuffer buf = ByteBuffer.allocate(mask.length * 2);
		buf.put(mask);
		int maskOffset = TraceRegisterUtils.computeMaskOffset(register);
		int startVal = buf.position() + maskOffset;
		buf.position(startVal);
		buf.limit(buf.position() + byteLength);
		return buf;
	}

	public static RegisterValue finishBuffer(ByteBuffer buf, Register register) {
		byte[] arr = buf.array();
		if (!register.isBigEndian() && !register.isProcessorContext()) {
			ArrayUtils.reverse(arr, register.getBaseMask().length, buf.capacity());
		}
		return new RegisterValue(register, arr);
	}

	public static boolean isByteBound(Register register) {
		return register.getLeastSignificantBit() % 8 == 0 && register.getBitLength() % 8 == 0;
	}

	public static void requireByteBound(Register register) {
		if (!isByteBound(register)) {
			throw new IllegalArgumentException(
				"Cannot work with sub-byte registers. Consider a parent instead.");
		}
	}

	public static TraceRegisterContainer getRegisterContainer(TraceThread thread, int frameLevel) {
		return getRegisterContainer(thread.getObject(), frameLevel);
	}

	public static TraceRegisterContainer getRegisterContainer(TraceStackFrame frame) {
		// Use frameLevel = 0, because we're already in the frame
		// so, no wild cards between here and registers
		return getRegisterContainer(frame.getObject(), 0);
	}

	public static TraceRegisterContainer getRegisterContainer(TraceObject object, int frameLevel) {
		if (object.getSchema()
				.getInterfaces()
				.contains(TraceRegisterContainer.class)) {
			return object.queryInterface(TraceRegisterContainer.class);
		}
		TraceObject contObj = object.findRegisterContainer(frameLevel);
		return contObj == null ? null : contObj.queryInterface(TraceRegisterContainer.class);
	}

	public static AddressSpace getRegisterAddressSpace(TraceRegisterContainer cont,
			boolean createIfAbsent) {
		TraceObject object = cont.getObject();
		Trace trace = object.getTrace();
		String name = object.getCanonicalPath().toString();
		AddressSpace regSpace = trace.getBaseAddressFactory().getRegisterSpace();
		if (createIfAbsent) {
			return trace.getMemoryManager().getOrCreateOverlayAddressSpace(name, regSpace);
		}
		return trace.getBaseAddressFactory().getAddressSpace(name);
	}

	public static AddressSpace getRegisterAddressSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent) {
		return getRegisterAddressSpace(getRegisterContainer(thread, frameLevel), createIfAbsent);
	}

	public static AddressSpace getRegisterAddressSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getRegisterAddressSpace(getRegisterContainer(frame), createIfAbsent);
	}

	public static TraceThread getThread(Trace trace, AddressSpace space) {
		if (space.isMemorySpace()) {
			return null;
		}
		TraceObject regs = trace.getObjectManager()
				.getObjectByCanonicalPath(KeyPath.parse(space.getName()));
		if (regs == null) {
			return null;
		}
		return regs.queryCanonicalAncestorsInterface(TraceThread.class).findAny().orElse(null);
	}

	public static int getFrameLevel(Trace trace, AddressSpace space) {
		if (space.isMemorySpace()) {
			return 0;
		}
		TraceObject regs = trace.getObjectManager()
				.getObjectByCanonicalPath(KeyPath.parse(space.getName()));
		if (regs == null) {
			return 0;
		}
		return regs.queryCanonicalAncestorsInterface(TraceStackFrame.class)
				.findAny()
				.map(r -> r.getLevel())
				.orElse(0);
	}
}
