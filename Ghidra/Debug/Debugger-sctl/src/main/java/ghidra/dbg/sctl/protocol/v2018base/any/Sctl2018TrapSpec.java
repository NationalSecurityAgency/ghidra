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
package ghidra.dbg.sctl.protocol.v2018base.any;

import ghidra.comm.packet.annot.BitmaskEncoded;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.dbg.sctl.protocol.common.AbstractSctlTrapSpec;

public class Sctl2018TrapSpec extends AbstractSctlTrapSpec {
	public static final BitmaskSet<Flag> FLAGS_HARDWARE =
		BitmaskSet.of(Flag.TRAP_HR, Flag.TRAP_HW, Flag.TRAP_HX);

	public enum Flag implements BitmaskUniverse {
		/** Suspend execution when trapped */
		ACTION_STOP(0),
		/** Snapshot target when trapped */
		ACTION_SNAP(1 << 0),
		/** Trap on execute using a software breakpoint */
		TRAP_SW(0),
		/** Trap on read using a hardware breakpoint */
		TRAP_HR(1 << 1),
		/** Trap on write using a hardware breakpoint */
		TRAP_HW(1 << 2),
		/** Trap on execute using a hardware breakpoint */
		TRAP_HX(1 << 3);

		private final long mask;

		Flag(long mask) {
			this.mask = mask;
		}

		@Override
		public long getMask() {
			return mask;
		}
	}

	public Sctl2018TrapSpec() {
	}

	@Override
	public void setAddress(long addr) {
		this.addr = addr;
	}

	@Override
	public long getAddress() {
		return addr;
	}

	@Override
	public void setLength(long len) {
		this.len = len;
	}

	@Override
	public long getLength() {
		return len;
	}

	@Override
	public void setActionStop() {
		mode.remove(Flag.ACTION_SNAP);
	}

	@Override
	public boolean isActionStop() {
		return !mode.contains(Flag.ACTION_SNAP);
	}

	@Override
	public void setActionSnap() {
		mode.add(Flag.ACTION_SNAP);
	}

	@Override
	public boolean isActionSnap() {
		return mode.contains(Flag.ACTION_SNAP);
	}

	@Override
	public void setSoftwareExecute() {
		mode.removeAll(FLAGS_HARDWARE);
	}

	@Override
	public boolean isSoftwareExecute() {
		return !mode.containsAny(FLAGS_HARDWARE);
	}

	@Override
	public void setHardware(boolean read, boolean write, boolean execute) {
		if (read) {
			mode.add(Flag.TRAP_HR);
		}
		else {
			mode.remove(Flag.TRAP_HR);
		}
		if (write) {
			mode.add(Flag.TRAP_HW);
		}
		else {
			mode.remove(Flag.TRAP_HW);
		}
		if (execute) {
			mode.add(Flag.TRAP_HX);
		}
		else {
			mode.remove(Flag.TRAP_HX);
		}
	}

	@Override
	public boolean isHardware() {
		return mode.containsAny(FLAGS_HARDWARE);
	}

	@Override
	public boolean isHardwareRead() {
		return mode.contains(Flag.TRAP_HR);
	}

	@Override
	public boolean isHardwareWrite() {
		return mode.contains(Flag.TRAP_HW);
	}

	@Override
	public boolean isHardwareExecute() {
		return mode.contains(Flag.TRAP_HX);
	}

	/**
	 * Flags identifying when to trap and what action to take
	 * 
	 * Note that {@link Flag#ACTION_STOP} and {@link Flag#ACTION_SNAP} are mutually exclusive. Note
	 * also, that {@link Flag#TRAP_SW} is mutually exclusive with the {@link Flag#TRAP_HR},
	 * {@link Flag#TRAP_HW}, and {@link Flag#TRAP_HX} flags. The hardware trap flags may be used in
	 * combination, and the server must accept such requests.
	 */
	@PacketField
	@BitmaskEncoded(universe = Flag.class)
	public BitmaskSet<Flag> mode = BitmaskSet.of();

	/**
	 * The address of the (start of) the trap
	 * 
	 * Note that different platforms may place different restrictions on the address and length of
	 * hardware traps.
	 */
	@PacketField
	public long addr;

	/**
	 * For hardware breakpoints, the length of the trap
	 * 
	 * Note that different platforms may place different restrictions on the address and length of
	 * hardware traps.
	 */
	@PacketField
	public long len;
}
