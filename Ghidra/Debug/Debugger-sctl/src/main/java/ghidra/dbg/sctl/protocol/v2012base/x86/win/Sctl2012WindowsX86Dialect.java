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
package ghidra.dbg.sctl.protocol.v2012base.x86.win;

import java.util.Set;

import ghidra.comm.packet.AbstractPacketFactory;
import ghidra.comm.packet.PacketFactory;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.common.AbstractSctlContext;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * The "x86-win-2012" SCTL dialect
 * 
 * Note that support for Windows was nascent when the specification was implemented. In many cases,
 * the packet formats are the same as those from Linux. In other cases, the specs say things are
 * undefined, but the reference stub behaves as it does on Linux, anyway. Reasonable guesses are
 * implemented here, but this client has not been tested with the official SCTL process controller
 * for Windows.
 */
public enum Sctl2012WindowsX86Dialect implements SctlDialect {
	INSTANCE;

	public static class Sctl2012WindowsX86PacketFactory extends AbstractPacketFactory {
		{
			useFor(AbstractSctlContext.class, Sctl2012WindowsX86Context.class);
		}
	}

	public static final String SYS_VERSION = "x86-win-2012";
	public static final String PLATFORM = "win-x64";
	private static final PacketFactory FACTORY = new Sctl2012WindowsX86PacketFactory();

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
		if (events.contains(Evkind.Efork)) {
			return TargetExecutionState.RUNNING;
		}
		if (events.contains(Evkind.Eclone)) {
			return TargetExecutionState.RUNNING;
		}
		return TargetExecutionState.STOPPED;
	}

	@Override
	public String getSolePlatform() {
		return PLATFORM;
	}
}
