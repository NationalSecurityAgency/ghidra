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

import java.lang.reflect.InvocationTargetException;
import java.util.Set;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.dbg.sctl.protocol.*;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * An interface for a SCTL dialect
 * 
 * To handle different versions and variants, SCTL supports the notion dialects. When negotiating a
 * connection, the client lists its version and dialects, and the server selects from those offered.
 * The client supports multiple dialects, each implementing this interface.
 */
public interface SctlDialect {
	public SctlDialect NULL_DIALECT = SctlNullDialect.INSTANCE;

	/**
	 * Get the system version string to offer in version negotiation
	 * 
	 * @return the system version string
	 */
	public String getSysVersion();

	/**
	 * Get the full version string to offer in version negotiation
	 * 
	 * @return the full version string
	 */
	public default String getFullVersion() {
		return SctlVersionInfo.SCTL_VERSION + ":" + getSysVersion();
	}

	/**
	 * Get the packet factory that provides dialect-specific packet formats
	 * 
	 * @return the packet factory for this dialect
	 */
	public PacketFactory getPacketFactory();

	/**
	 * Check whether this dialect is aware of other clients using the same server
	 * 
	 * @return true if supported, false otherwise
	 */
	public boolean isBusSupported();

	/**
	 * Check whether this dialect supports register selection
	 * 
	 * @return true if supported, false otherwise
	 */
	public boolean isRegisterSelectionSupported();

	/**
	 * Get the state of a CTL (thread) after an event is reported
	 * 
	 * @param events the flags describing the event
	 * @return the state of the CTL
	 */
	public TargetExecutionState stateAfterEvent(Set<Evkind> events);

	/**
	 * If the dialect supports only one platform, get that platform
	 * 
	 * @return the platform
	 * @throws UnsupportedOperationException if the dialect supports multiple platforms
	 */
	public String getSolePlatform();

	/**
	 * Create the root packet type for this dialect
	 * 
	 * @param tag the tag
	 * @param cmd the command
	 * @return the packet
	 */
	default public AbstractSelSctlPacket createSel(int tag, SctlPacket cmd) {
		AbstractSelSctlPacket pkt = create(AbstractSelSctlPacket.class);
		pkt.tag = tag;
		pkt.sel = cmd;
		return pkt;
	}

	/**
	 * A convenience for invoking the dialect's packet factory
	 * 
	 * @param cls the packet class to instantiate
	 * @return the new packet
	 */
	default public <T extends Packet> T create(Class<T> cls) {
		try {
			return getPacketFactory().newPacket(cls);
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new AssertionError(e);
		}
	}
}
