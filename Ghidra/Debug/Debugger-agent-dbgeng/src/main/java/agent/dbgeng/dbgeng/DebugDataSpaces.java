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
package agent.dbgeng.dbgeng;

import java.nio.ByteBuffer;
import java.util.*;

import com.sun.jna.platform.win32.COM.COMException;

import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.util.Msg;

/**
 * A wrapper for {@code IDebugDataSpaces} and its newer variants.
 */
public interface DebugDataSpaces {
	public enum PageState {
		COMMIT(0x1000), FREE(0x10000), RESERVE(0x2000);

		private final int val;

		private PageState(int val) {
			this.val = val;
		}

		public static PageState byValue(int val) {
			for (PageState state : values()) {
				if (state.val == val) {
					return state;
				}
			}
			Msg.warn(PageState.class, "No such value: 0x" + Integer.toHexString(val));
			return null;
		}
	}

	public enum PageProtection implements BitmaskUniverse {
		NOACCESS(1 << 0, false, false, false), //
		READONLY(1 << 1, true, false, false), //
		READWRITE(1 << 2, true, true, false), //
		WRITE_COPY(1 << 3, true, true, false), // Becomes READWRITE after copy
		EXECUTE(1 << 4, false, false, true), //
		EXECUTE_READ(1 << 5, true, false, true), //
		EXECUTE_READWRITE(1 << 6, true, true, true), //
		EXECUTE_WRITECOPY(1 << 7, true, true, true), //
		//
		GUARD(1 << 8, false, false, false), //
		NOCACHE(1 << 9, false, false, false), //
		WRITECOMBINE(1 << 10, false, false, false), //
		;

		private PageProtection(int mask, boolean isRead, boolean isWrite, boolean isExecute) {
			this.mask = mask;
			this.isRead = isRead;
			this.isWrite = isWrite;
			this.isExecute = isExecute;
		}

		final int mask;
		final boolean isRead;
		final boolean isWrite;
		final boolean isExecute;

		@Override
		public long getMask() {
			return mask;
		}

		public boolean isRead() {
			return isRead;
		}

		public boolean isWrite() {
			return isWrite;
		}

		public boolean isExecute() {
			return isExecute;
		}
	}

	public enum PageType {
		NONE(0), //
		IMAGE(0x1000000), //
		MAPPED(0x40000), //
		PRIVATE(0x20000), //
		;

		private final int val;

		private PageType(int val) {
			this.val = val;
		}

		public static PageType byValue(int val) {
			for (PageType type : values()) {
				if (type.val == val) {
					return type;
				}
			}
			Msg.warn(PageType.class, "No such value: 0x" + Integer.toHexString(val));
			return null;
		}
	}

	public static class DebugMemoryBasicInformation {
		public final long baseAddress;
		public final long allocationBase;
		public final Set<PageProtection> allocationProtect;
		public final long regionSize;
		public final PageState state;
		public final Set<PageProtection> protect;
		public final PageType type;

		public DebugMemoryBasicInformation(long baseAddress, long allocationBase,
				BitmaskSet<PageProtection> allocationProtect, long regionSize, PageState state,
				BitmaskSet<PageProtection> protect, PageType type) {
			this.baseAddress = baseAddress;
			this.allocationBase = allocationBase;
			this.allocationProtect = Collections.unmodifiableSet(allocationProtect);
			this.regionSize = regionSize;
			this.state = state;
			this.protect = Collections.unmodifiableSet(protect);
			this.type = type;
		}

		@Override
		public String toString() {
			return "<DebugMemoryBasicInformation:\n" + //
				"    baseAddress=" + Long.toHexString(baseAddress) + "h,\n" + //
				"    allocationBase=" + Long.toHexString(allocationBase) + "h,\n" + //
				"    allocationProtect=" + allocationProtect + ",\n" + //
				"    regionSize=" + Long.toHexString(regionSize) + "h,\n" + //
				"    state=" + state + ",\n" + //
				"    protect=" + protect + ",\n" + //
				"    type=" + type + "\n" + //
				">";
		}

		@Override
		public int hashCode() {
			return Objects.hash(baseAddress, allocationBase, allocationProtect, regionSize, state,
				protect, type);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof DebugMemoryBasicInformation)) {
				return false;
			}
			DebugMemoryBasicInformation that = (DebugMemoryBasicInformation) obj;
			if (this.baseAddress != that.baseAddress) {
				return false;
			}
			if (this.allocationBase != that.allocationBase) {
				return false;
			}
			if (!this.allocationProtect.equals(that.allocationProtect)) {
				return false;
			}
			if (this.regionSize != that.regionSize) {
				return false;
			}
			if (this.state != that.state) {
				return false;
			}
			if (!this.protect.equals(that.protect)) {
				return false;
			}
			if (this.type != that.type) {
				return false;
			}
			return true;
		}
	}

	int readVirtual(long offset, ByteBuffer into, int len);

	int writeVirtual(long offset, ByteBuffer from, int len);

	int readVirtualUncached(long offset, ByteBuffer into, int len);

	int writeVirtualUncached(long offset, ByteBuffer from, int len);

	int readPhysical(long offset, ByteBuffer into, int len);

	int writePhysical(long offset, ByteBuffer from, int len);

	int readControl(int processor, long offset, ByteBuffer into, int len);

	int writeControl(int processor, long offset, ByteBuffer from, int len);

	int readBusData(int busDataType, int busNumber, int slotNumber, long offset, ByteBuffer into,
			int len);

	int writeBusData(int busDataType, int busNumber, int slotNumber, long offset, ByteBuffer from,
			int len);

	int readIo(int interfaceType, int busNumber, int addressSpace, long offset, ByteBuffer into,
			int len);

	int writeIo(int interfaceType, int busNumber, int addressSpace, long offset, ByteBuffer from,
			int len);

	long readMsr(int msr);

	void writeMsr(int msr, long value);

	int readDebuggerData(int offset, ByteBuffer into, int len);

	DebugMemoryBasicInformation queryVirtual(long offset);

	/**
	 * A shortcut for iterating over virtual memory regions.
	 * 
	 * This operates by calling {@link #queryVirtual(long)} to get each next entry, starting at an
	 * offset of -start-, adding the size of the returned region to determine the offset for the
	 * next call.
	 * 
	 * @param start the starting offset
	 * @return an iterator over virtual memory regions after the given start
	 */
	default Iterable<DebugMemoryBasicInformation> iterateVirtual(long start) {
		return new Iterable<DebugMemoryBasicInformation>() {
			@Override
			public Iterator<DebugMemoryBasicInformation> iterator() {
				return new Iterator<DebugMemoryBasicInformation>() {
					private long last = start;
					private long offset = start;
					private DebugMemoryBasicInformation next = doGetNext();

					private DebugMemoryBasicInformation getNext() {
						if (Long.compareUnsigned(last, offset) < 0) {
							return doGetNext();
						}
						return null;
					}

					private DebugMemoryBasicInformation doGetNext() {
						try {
							DebugMemoryBasicInformation info = queryVirtual(offset);
							last = offset;
							if (info != null) {
								offset += info.regionSize;
							}
							return info;
						}
						catch (COMException e) {
							if (!COMUtilsExtra.isE_NOINTERFACE(e)) {
								throw e;
							}
							return null;
						}
					}

					@Override
					public boolean hasNext() {
						return next != null;
					}

					@Override
					public DebugMemoryBasicInformation next() {
						DebugMemoryBasicInformation ret = next;
						next = getNext();
						return ret;
					}
				};
			}
		};
	}
}
