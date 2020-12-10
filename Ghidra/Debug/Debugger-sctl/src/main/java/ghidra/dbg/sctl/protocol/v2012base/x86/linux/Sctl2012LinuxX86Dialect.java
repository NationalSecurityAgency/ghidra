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

import java.util.Set;

import ghidra.comm.packet.AbstractPacketFactory;
import ghidra.comm.packet.PacketFactory;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.common.*;
import ghidra.dbg.sctl.protocol.common.notify.AbstractSctlForkNotification;
import ghidra.dbg.sctl.protocol.common.notify.AbstractSctlSnapNotification;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.dbg.sctl.protocol.v2012base.*;
import ghidra.dbg.sctl.protocol.v2012base.x86.SctlX86Context;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * The "x86-linux-2012" SCTL dialect
 */
public enum Sctl2012LinuxX86Dialect implements SctlDialect {
	INSTANCE;

	public static class Sctl2012LinuxX86PacketFactory extends AbstractPacketFactory {
		{
			useFor(AbstractSelSctlPacket.class, SelSctl2012Packet.class);

			useFor(AbstractSctlAttachReply.class, Sctl2012AttachReply.class);
			useFor(AbstractSctlLaunchReply.class, Sctl2012LaunchReply.class);
			useFor(AbstractSctlSnapshotReply.class, Sctl2012SnapshotReply.class);

			useFor(AbstractSctlForkNotification.class, Sctl2012ForkNotification.class);
			useFor(AbstractSctlSnapNotification.class, Sctl2012SnapNotification.class);

			useFor(AbstractSctlContext.class, SctlX86Context.class);
			useFor(AbstractSctlProcessList.class, Sctl2012LinuxProcessList.class);
			useFor(AbstractSctlStatus.class, Sctl2012LinuxStatus.class);
			useFor(AbstractSctlTrapSpec.class, Sctl2012LinuxTrapSpec.class);
		}
	}

	public static final String SYS_VERSION = "x86-linux-2012";
	public static final String PLATFORM = "linux-x86_64";
	private static final PacketFactory FACTORY = new Sctl2012LinuxX86PacketFactory();

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
		return false;
	}

	@Override
	public TargetExecutionState stateAfterEvent(Set<Evkind> events) {
		if (events.contains(Evkind.Eexit)) {
			return TargetExecutionState.TERMINATED;
		}
		return TargetExecutionState.STOPPED;
	}

	@Override
	public String getSolePlatform() {
		return PLATFORM;
	}
}
