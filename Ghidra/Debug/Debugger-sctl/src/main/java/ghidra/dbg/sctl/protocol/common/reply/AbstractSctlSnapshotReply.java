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
package ghidra.dbg.sctl.protocol.common.reply;

import ghidra.comm.packet.annot.OptionalField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.dialect.HasOptionalProcessID;
import ghidra.dbg.sctl.protocol.AbstractSctlReply;
import ghidra.dbg.sctl.protocol.common.AbstractSctlContext;

/**
 * Format for the {@code Rsnap} SCTL message
 */
public abstract class AbstractSctlSnapshotReply extends AbstractSctlReply
		implements HasOptionalProcessID {
	@PacketField
	public long spwnid;

	@PacketField
	@OptionalField
	public AbstractSctlContext ctx;
}
