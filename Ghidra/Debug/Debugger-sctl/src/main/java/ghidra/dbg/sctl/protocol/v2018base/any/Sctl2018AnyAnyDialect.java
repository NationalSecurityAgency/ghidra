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
import ghidra.dbg.sctl.protocol.v2018base.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

public enum Sctl2018AnyAnyDialect implements SctlDialect {
	INSTANCE;

	protected static class Sctl2018BusAnyAnyPacketFactory extends AbstractPacketFactory {
		{
			useFor(AbstractSelSctlPacket.class, SelSctl2018Packet.class);

			useFor(AbstractSctlAttachReply.class, Sctl2018AttachReply.class);
			useFor(AbstractSctlLaunchReply.class, Sctl2018LaunchReply.class);
			useFor(AbstractSctlSnapshotReply.class, Sctl2018SnapshotReply.class);

			useFor(AbstractSctlForkNotification.class, Sctl2018ForkNotification.class);
			useFor(AbstractSctlSnapNotification.class, Sctl2018SnapNotification.class);

			useFor(AbstractSctlContext.class, Sctl2018Context.class);
			useFor(AbstractSctlProcessList.class, Sctl2018ProcessList.class);
			useFor(AbstractSctlStatus.class, Sctl2018Status.class);
			useFor(AbstractSctlTrapSpec.class, Sctl2018TrapSpec.class);

			useFor(AbstractSctlObjectEntry.class, Sctl2018ObjectEntry.class);
		}
	}

	public static final String SYS_VERSION = "any-any-2018";
	private static final PacketFactory FACTORY = new Sctl2018BusAnyAnyPacketFactory();

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
		return true;
	}

	@Override
	public TargetExecutionState stateAfterEvent(Set<Evkind> events) {
		if (events.contains(Evkind.Erunning)) {
			return TargetExecutionState.RUNNING;
		}
		return TargetExecutionState.STOPPED;
	}

	@Override
	public String getSolePlatform() {
		throw new UnsupportedOperationException();
	}
}
