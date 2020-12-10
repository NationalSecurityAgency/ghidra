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
package ghidra.dbg.sctl.dialect;

import java.util.Set;

import ghidra.comm.packet.AbstractPacketFactory;
import ghidra.comm.packet.PacketFactory;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

public enum SctlNullDialect implements SctlDialect {
	INSTANCE;

	public static class SctlNullPacketFactory extends AbstractPacketFactory {
		{
			useFor(AbstractSelSctlPacket.class, SelSctlNullDialectPacket.class);
		}
	}

	public static final String SYS_VERSION = "(negotiating)";
	private static final PacketFactory FACTORY = new SctlNullPacketFactory();

	@Override
	public String getSysVersion() {
		return SYS_VERSION;
	}

	@Override
	public PacketFactory getPacketFactory() {
		return FACTORY;
	}

	@Override
	public boolean isBusSupported() {
		return false;
	}

	@Override
	public boolean isRegisterSelectionSupported() {
		throw new IllegalStateException("Dialect has not been negotiated");
	}

	@Override
	public TargetExecutionState stateAfterEvent(Set<Evkind> events) {
		throw new IllegalStateException("Dialect has not been negotiated");
	}

	@Override
	public String getSolePlatform() {
		throw new IllegalStateException("Dialect has not been negotiated");
	}
}
