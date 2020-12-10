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
package ghidra.dbg.sctl.protocol.v2018base;

import java.util.Map;

import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.SctlPacket;
import ghidra.dbg.sctl.protocol.consts.Mkind;
import ghidra.dbg.sctl.protocol.v2012ext.SelSctl2012ExtPacket;

public class SelSctl2018Packet extends AbstractSelSctlPacket {
	public static final Map<Mkind, Class<? extends SctlPacket>> METHOD_MAP =
		typeMap(Mkind.class, SctlPacket.class) //
				.putAll(SelSctl2012ExtPacket.METHOD_MAP) //
				.put(Mkind.Tenumctx, SctlEnumerateContextRequest.class) //
				.put(Mkind.Renumctx, SctlEnumerateContextReply.class) //
				.put(Mkind.Tchoosectx, SctlChooseContextRequest.class) //
				.put(Mkind.Rchoosectx, SctlChooseContextReply.class) //
				.put(Mkind.Tfocus, SctlFocusRequest.class) //
				.put(Mkind.Rfocus, SctlFocusReply.class) // 
				.put(Mkind.Tgetchildren, SctlGetElementsRequest.class) //
				.put(Mkind.Rgetchildren, SctlGetElementsReply.class) // 
				.put(Mkind.Tgetattributes, SctlGetAttributesRequest.class) //
				.put(Mkind.Rgetattributes, SctlGetAttributesReply.class) // 
				.build();
}
