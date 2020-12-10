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
package ghidra.dbg.sctl.protocol.v2012ext.x86.linux;

import java.util.Set;

import ghidra.comm.packet.PacketFactory;
import ghidra.dbg.sctl.client.SctlExtension;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.dbg.sctl.protocol.v2012base.x86.linux.Sctl2012LinuxX86Dialect;
import ghidra.dbg.sctl.protocol.v2012base.x86.linux.Sctl2012LinuxX86Dialect.Sctl2012LinuxX86PacketFactory;
import ghidra.dbg.sctl.protocol.v2012ext.SelSctl2012ExtPacket;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * "Bus" extension to SCTL's Linux x86 2012 dialect.
 * 
 * SCTL-Bus is an extension (read "hack") added by Ghidra's implementation of SCTL. Since SCTL was
 * designed to give L1 complete and <em>exclusive</em> control of a remote process, asynchronous
 * notifications were only required for execution events. The "Bus" variant allows multiple
 * controllers to cooperate and stay in sync. The controller must now also listen for requests from
 * other controllers as well as for the responses those requests generate.
 * 
 * To distinguish each controller, the tag field is structured as follows:
 * 
 * <pre>
 *   31-24            23-0
 * +--------+------------------------+
 * |   ID   |          Tag           |
 * +--------+------------------------+
 * </pre>
 * 
 * Where ID (the highest-order byte) identifies the controller and the remaining bits uniquely
 * identify the request. Each client should be assigned its ID statically. No method of dynamic
 * selection has been explored, though random selection may be available in future versions.
 * 
 * The extension provides more flexibility in debugger connections than is immediately apparent.
 * First, the setup is backward compatible with non-bus SCTL. A client can offer both variants, and
 * a non-bus SCTL server ought to select the non-bus variant. Furthermore, a bus-enabled stub can
 * agree to a non-bus controller without any changes in protocol, except to give the controller
 * exclusive access to the bus.
 * 
 * Second, a non-bus stub need not be aware that multiple controllers are present. A proxy bus can
 * be placed in front of the stub. It need only negotiate the versions. So long as all controllers
 * speak the same version, it can just forward all packets on all connections -- as a bus should.
 * 
 * Third, for stubs that operate by integrating a host debugger, the stub may pretend the debugger's
 * UI is another controller on the bus. This enables it to keep the connected controller(s) in sync
 * with commands issued directly in the debugger's UI.
 * 
 * For terminology, consider the typical example setup for debugging on Linux with Ghidra:
 * 
 * <pre>
 * +--------+      +------+            +-----+        +-----------+
 * | Ghidra |-SCTL-| stub |-pty:GDB/MI-| gdb |-ptrace-| /bin/echo |
 * +--------+      +------+            +-----+        +-----------+
 * </pre>
 * 
 * Ghidra, a.k.a, the Ghidra debugger, is acting as the SCTL client. gdb is the external or remote
 * debugger. A custom SCTL stub controls gdb via a pty with GDB/MI. As an example,
 * <code>/bin/echo</code> is the program image for the target process.
 * 
 * In this setup, Ghidra does not have exclusive control of the target process. Ghidra cooperates
 * with the external debugger, so there is a need to communicate to Ghidra control commands issued
 * by the user to the external debugger. In this case, the stub should prefer to use SCTL's defined
 * notification commands where applicable. For example, if a process forks, the stub ought to issue
 * the fork notification rather than synthesizing a launch command. When the stub synthesizes a
 * control command, it must also synthesize the successful reply. It would synthesize these commands
 * using incrementing tags and a bus ID different than the client's ID.
 * 
 * The requests that may be synthesized by the stub include:
 * <ul>
 * <li><b>launch</b> - to notify the clients of a launched process, excluding those created by fork
 * or clone, since those already have defined notifications.</li>
 * <li><b>attach</b> - to notify the clients of an attached process, excluding those created by fork
 * or clone, since those already have defined notifications.</li>
 * <li><b>step</b> - to notify the clients that a step was issued externally.</li>
 * <li><b>stop</b> - to notify the clients that a stop was issued externally.</li>
 * <li><b>cont</b> - to notify the clients that a continue was issued externally.</li>
 * <li><b>kill</b> - to notify the clients that a kill was issued externally. This need only be sent
 * if a process is explicitly terminated by the debugger. For processes that exit in the usual way,
 * use the usual SCTL notify message.</li>
 * <li><b>detach</b> - to notify the clients that a detach was issued externally. This need only be
 * sent if the user explicitly detached from a process. For processes that exit in the usual way,
 * use the usual SCTL notify message.</li>
 * <li><b>settrap</b> - to notify the clients that the user created a breakpoint.</li>
 * <li><b>clrtrap</b> - to notify the clients that the user deleted a breakpoint.</li>
 * <li><b>setctx</b> - to notify the clients that the user modified one or more registers.</li>
 * </ul>
 * 
 * These rules are designed to prevent a stub from giving a client any false impressions. They need
 * not be followed precisely. For example, if a stop is implemented by sending the target SIGINT,
 * then it is acceptable for the stub to send a signal notification even if the stop was requested
 * from the debugger's UI.
 * 
 * If bus mode is available, the stub ought to sync the client to its current state. If a proxy is
 * used, and it keeps a log, it could replay it on any new channel. If it is smart, it can cull that
 * log to eliminate messages that are no longer relevant to the current state. A stub that is also a
 * controller ought to synthesize the necessary control commands upon connection.
 */
@SctlExtension("Bus or bidirectional requests")
public enum Sctl2012ExtLinuxX86Dialect implements SctlDialect {
	INSTANCE;

	public static class Sctl2012BusLinuxX86PacketFactory extends Sctl2012LinuxX86PacketFactory {
		{
			useFor(AbstractSelSctlPacket.class, SelSctl2012ExtPacket.class);
		}
	}

	public static final String SYS_VERSION = Sctl2012LinuxX86Dialect.SYS_VERSION + "-bus";
	public static final String PLATFORM = Sctl2012LinuxX86Dialect.PLATFORM;
	private static final PacketFactory FACTORY = new Sctl2012BusLinuxX86PacketFactory();

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
		return Sctl2012LinuxX86Dialect.INSTANCE.stateAfterEvent(events);
	}

	@Override
	public String getSolePlatform() {
		return PLATFORM;
	}
}
