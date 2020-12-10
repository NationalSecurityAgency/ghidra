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

import java.util.Map;

import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.SctlPacket;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.common.request.SctlPingRequest;
import ghidra.dbg.sctl.protocol.common.request.SctlVersionRequest;
import ghidra.dbg.sctl.protocol.consts.Mkind;

public class SelSctlNullDialectPacket extends AbstractSelSctlPacket {
	public static final Map<Mkind, Class<? extends SctlPacket>> METHOD_MAP =
		typeMap(Mkind.class, SctlPacket.class) //
				.put(Mkind.Rerror, SctlErrorReply.class) //
				.put(Mkind.Tversion, SctlVersionRequest.class) //
				.put(Mkind.Rversion, SctlVersionReply.class) //
				.put(Mkind.Tping, SctlPingRequest.class) //
				.put(Mkind.Rping, SctlPingReply.class) //
				.build();
}
