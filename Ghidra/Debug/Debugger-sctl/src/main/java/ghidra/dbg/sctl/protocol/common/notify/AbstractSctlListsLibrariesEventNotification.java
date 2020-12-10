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
package ghidra.dbg.sctl.protocol.common.notify;

import java.util.List;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.*;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractSctlContext;
import ghidra.dbg.sctl.protocol.common.SctlString;

/**
 * Factored common parts for {@code Eload} and {@code Eunload} SCTL events
 */
public abstract class AbstractSctlListsLibrariesEventNotification
		extends AbstractSctlEventNotification {

	public AbstractSctlListsLibrariesEventNotification() {
	}

	public AbstractSctlListsLibrariesEventNotification(List<PathBase> libs,
			AbstractSctlContext ctx) {
		this.libs = libs;
		this.ctx = ctx;
	}

	@PacketField
	public long nl;

	@PacketField
	@RepeatedField
	@CountedByField("nl")
	public List<PathBase> libs;

	// TODO: Modify this for any-any-2018. May just remove base....
	public static class PathBase extends Packet {
		public PathBase() {
		}

		public PathBase(String path, long base) {
			this.path = new SctlString(path);
			this.base = base;
		}

		@PacketField
		public SctlString path;

		@PacketField
		public long base;
	}

	@PacketField
	@OptionalField
	public AbstractSctlContext ctx;

	@Override
	public AbstractSctlContext getCtx() {
		return ctx;
	}
}
