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

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.v2012base.x86.SctlX86Context;

/**
 * The context packet for SCTL's x86-win dialect
 */
public class Sctl2012WindowsX86Context extends SctlX86Context {
	@PacketField(after = "gs")
	public long sig;
}
