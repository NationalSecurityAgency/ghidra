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
package ghidra.dbg.sctl.protocol.v2012base;

import java.util.Map;

import ghidra.dbg.sctl.dialect.SelSctlNullDialectPacket;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.SctlPacket;
import ghidra.dbg.sctl.protocol.common.notify.SctlEventNotify;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.common.request.*;
import ghidra.dbg.sctl.protocol.consts.Mkind;

public class SelSctl2012Packet extends AbstractSelSctlPacket {
	public SelSctl2012Packet() {
		super();
	}

	public SelSctl2012Packet(int tag, SctlPacket sel) {
		super(tag, sel);
	}

	public static final Map<Mkind, Class<? extends SctlPacket>> METHOD_MAP =
		typeMap(Mkind.class, SctlPacket.class) //
				.putAll(SelSctlNullDialectPacket.METHOD_MAP) //
				.put(Mkind.Aevent, SctlEventNotify.class) //
				.put(Mkind.Tps, SctlProcessListRequest.class) //
				.put(Mkind.Rps, SctlProcessListReply.class) //
				.put(Mkind.Tlaunch, SctlLaunchRequest.class) //
				.put(Mkind.Rlaunch, AbstractSctlLaunchReply.class) //
				.put(Mkind.Tattach, SctlAttachRequest.class) //
				.put(Mkind.Rattach, AbstractSctlAttachReply.class) //
				.put(Mkind.Tstat, SctlStatusRequest.class) //
				.put(Mkind.Rstat, SctlStatusReply.class) //
				.put(Mkind.Tcont, SctlContinueRequest.class) //
				.put(Mkind.Rcont, SctlContinueReply.class) //
				.put(Mkind.Tstop, SctlStopRequest.class) //
				.put(Mkind.Rstop, SctlStopReply.class) //
				.put(Mkind.Tstep, SctlStepRequest.class) //
				.put(Mkind.Rstep, SctlStepReply.class) //
				.put(Mkind.Tsnap, SctlSnapshotRequest.class) //
				.put(Mkind.Rsnap, AbstractSctlSnapshotReply.class) //
				.put(Mkind.Tkill, SctlKillRequest.class) //
				.put(Mkind.Rkill, SctlKillReply.class) //
				.put(Mkind.Tdetach, SctlDetachRequest.class) //
				.put(Mkind.Rdetach, SctlDetachReply.class) //
				.put(Mkind.Ttrace, SctlTraceRequest.class) //
				.put(Mkind.Rtrace, SctlTraceReply.class) //
				.put(Mkind.Tsettrap, SctlSetTrapRequest.class) //
				.put(Mkind.Rsettrap, SctlSetTrapReply.class) //
				.put(Mkind.Tclrtrap, SctlClearTrapRequest.class) //
				.put(Mkind.Rclrtrap, SctlClearTrapReply.class) //
				.put(Mkind.Tgetctx, SctlGetContextRequest.class) //
				.put(Mkind.Rgetctx, SctlGetContextReply.class) //
				.put(Mkind.Tsetctx, SctlSetContextRequest.class) //
				.put(Mkind.Rsetctx, SctlSetContextReply.class) //
				.put(Mkind.Tread, SctlReadRequest.class) //
				.put(Mkind.Rread, SctlReadReply.class) //
				.put(Mkind.Twrite, SctlWriteRequest.class) //
				.put(Mkind.Rwrite, SctlWriteReply.class) //
				.put(Mkind.Tlooksym, SctlLookupSymbolRequest.class) //
				.put(Mkind.Rlooksym, SctlLookupSymbolReply.class) //
				.put(Mkind.Tenumsym, SctlEnumerateSymbolsRequest.class) //
				.put(Mkind.Renumsym, SctlEnumerateSymbolsReply.class) //
				.put(Mkind.Tlooktype, SctlLookupTypeRequest.class) //
				.put(Mkind.Rlooktype, SctlLookupTypeReply.class) //
				.put(Mkind.Tenumtype, SctlEnumerateTypesRequest.class) //
				.put(Mkind.Renumtype, SctlEnumerateTypesReply.class) //
				.put(Mkind.Tlookaddr, SctlLookupAddressRequest.class) //
				.put(Mkind.Rlookaddr, SctlLookupAddressReply.class) //
				.put(Mkind.Tenumloc, SctlEnumerateLocalsRequest.class) //
				.put(Mkind.Renumloc, SctlEnumerateLocalsReply.class) //
				.put(Mkind.Tenumseg, SctlEnumerateSegmentsRequest.class) //
				.put(Mkind.Renumseg, SctlEnumerateSegmentsReply.class) //
				.put(Mkind.Tnames, SctlNamesRequest.class) //
				.put(Mkind.Rnames, SctlNamesReply.class) //
				.put(Mkind.Tunwind1, SctlUnwindOneFrameRequest.class) //
				.put(Mkind.Runwind1, SctlUnwindOneFrameReply.class) //
				.put(Mkind.Tlooksrc, SctlLookupSourceRequest.class) //
				.put(Mkind.Rlooksrc, SctlLookupSourceReply.class) //
				.put(Mkind.Tlookpc, SctlLookupProgramCounterRequest.class) //
				.put(Mkind.Rlookpc, SctlLookupProgramCounterReply.class) //
				.build();
}
