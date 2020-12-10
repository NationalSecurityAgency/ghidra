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
package ghidra.dbg.sctl.protocol.common;

import ghidra.comm.packet.Packet;

/**
 * A trap specification
 * 
 * This is a dialect-defined format. This is effectively an interface defining the union of options
 * for all supported dialects. If a dialect does not support an option, it must throw an
 * {@link UnsupportedOperationException}. For {@code get} operations, the dialect should return what
 * is implied by the restrictions of the dialect.
 */
public abstract class AbstractSctlTrapSpec extends Packet {
	public abstract void setAddress(long address);

	public abstract long getAddress();

	public abstract void setLength(long length);

	public abstract long getLength();

	public abstract void setActionStop();

	public abstract boolean isActionStop();

	public abstract void setActionSnap();

	public abstract boolean isActionSnap();

	public abstract void setSoftwareExecute();

	public abstract boolean isSoftwareExecute();

	public abstract void setHardware(boolean read, boolean write, boolean execute);

	public abstract boolean isHardware();

	public abstract boolean isHardwareRead();

	public abstract boolean isHardwareWrite();

	public abstract boolean isHardwareExecute();
}
