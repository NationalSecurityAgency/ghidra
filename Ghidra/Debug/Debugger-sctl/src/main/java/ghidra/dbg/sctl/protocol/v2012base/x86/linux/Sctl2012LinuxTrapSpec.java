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
package ghidra.dbg.sctl.protocol.v2012base.x86.linux;

import ghidra.comm.packet.annot.BitmaskEncoded;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.dbg.sctl.protocol.common.AbstractSctlTrapSpec;

/**
 * The format of {@code bytes[]} in SCTL's {@code Tsettrap} for Linux dialects
 */
public class Sctl2012LinuxTrapSpec extends AbstractSctlTrapSpec {
	public enum Flag implements BitmaskUniverse {
		ACTION_STOP(0), ACTION_SNAP(1 << 0);

		private final long mask;

		Flag(long mask) {
			this.mask = mask;
		}

		@Override
		public long getMask() {
			return mask;
		}
	}

	public Sctl2012LinuxTrapSpec() {
		this.mode = BitmaskSet.of();
	}

	public Sctl2012LinuxTrapSpec(BitmaskSet<Flag> mode, long addr) {
		this.mode = mode;
		this.addr = addr;
	}

	@Override
	public void setAddress(long address) {
		this.addr = address;
	}

	@Override
	public long getAddress() {
		return addr;
	}

	@Override
	public void setLength(long length) {
		if (length == 1) {
			// Yeah
			return;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLength() {
		return 1;
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
		// Yeah
	}

	@Override
	public boolean isSoftwareExecute() {
		return true;
	}

	@Override
	public void setHardware(boolean read, boolean write, boolean execute) {
		if (!read && !write && !execute) {
			// Yeah
			return;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isHardware() {
		return false;
	}

	@Override
	public boolean isHardwareRead() {
		return false;
	}

	@Override
	public boolean isHardwareWrite() {
		return false;
	}

	@Override
	public boolean isHardwareExecute() {
		return false;
	}

	@PacketField
	@BitmaskEncoded(universe = Flag.class)
	public BitmaskSet<Flag> mode;

	@PacketField
	public long addr;
}
