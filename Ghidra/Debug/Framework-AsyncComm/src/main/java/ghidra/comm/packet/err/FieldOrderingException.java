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
package ghidra.comm.packet.err;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.fields.PacketField;
import ghidra.graph.algo.SorterException;

/**
 * Occurs when the field order is not fully specified or circular
 * 
 * When extending another packet type, added fields must be ordered explicitly with respect to the
 * fields of the super type(s). This is accomplished using the {@link PacketField#before()} and
 * {@link PacketField#after()} attributes. Fields declared within the same class are assumed to be
 * in declaration order. Once applied, these rules form a graph and a topological sort is attempted.
 * The sort could fail if the rules form a cycle, or if multiple orders are possible without
 * breaking one or more rules. If the sort fails, this exception is thrown upon packet registration.
 */
public class FieldOrderingException extends PacketDeclarationException {
	public FieldOrderingException(Class<? extends Packet> packet, String msg,
			SorterException cause) {
		super(packet, msg, cause);
	}
}
