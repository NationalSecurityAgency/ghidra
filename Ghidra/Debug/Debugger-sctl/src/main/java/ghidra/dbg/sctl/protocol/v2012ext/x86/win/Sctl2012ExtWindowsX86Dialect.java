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
package ghidra.dbg.sctl.protocol.v2012ext.x86.win;

import java.util.Set;

import ghidra.comm.packet.PacketFactory;
import ghidra.dbg.sctl.client.SctlExtension;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.dbg.sctl.protocol.v2012base.x86.win.Sctl2012WindowsX86Dialect;
import ghidra.dbg.sctl.protocol.v2012base.x86.win.Sctl2012WindowsX86Dialect.Sctl2012WindowsX86PacketFactory;
import ghidra.dbg.sctl.protocol.v2012ext.SelSctl2012ExtPacket;
import ghidra.dbg.sctl.protocol.v2012ext.x86.linux.Sctl2012ExtLinuxX86Dialect;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * "Bidirectional" extension to the Windows x86 2012 SCTL dialect.
 *
 * @see Sctl2012ExtLinuxX86Dialect
 */
@SctlExtension("Bus or bidirectional requests")
public enum Sctl2012ExtWindowsX86Dialect implements SctlDialect {
	INSTANCE;

	public static class Sctl2012BusWindowsX86PacketFactory extends Sctl2012WindowsX86PacketFactory {
		{
			useFor(AbstractSelSctlPacket.class, SelSctl2012ExtPacket.class);
		}
	}

	public static final String SYS_VERSION = Sctl2012WindowsX86Dialect.SYS_VERSION + "-bus";
	public static final String PLATFORM = Sctl2012WindowsX86Dialect.PLATFORM;
	private static final PacketFactory FACTORY = new Sctl2012BusWindowsX86PacketFactory();

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
		return true;
	}

	@Override
	public boolean isRegisterSelectionSupported() {
		return false;
	}

	@Override
	public TargetExecutionState stateAfterEvent(Set<Evkind> events) {
		if (events.contains(Evkind.Erunning)) {
			return TargetExecutionState.RUNNING;
		}
		if (events.contains(Evkind.Estopped)) {
			return TargetExecutionState.STOPPED;
		}
		return Sctl2012WindowsX86Dialect.INSTANCE.stateAfterEvent(events);
	}

	@Override
	public String getSolePlatform() {
		return PLATFORM;
	}
}
