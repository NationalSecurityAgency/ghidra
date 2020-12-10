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
package ghidra.dbg.sctl.server;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.async.AsyncLock;
import ghidra.dbg.sctl.client.SctlTargetObject;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.common.AbstractSctlContext;
import ghidra.dbg.sctl.protocol.common.AbstractSctlTrapSpec;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.common.request.*;
import ghidra.dbg.sctl.protocol.v2018base.*;

public class SctlSyntheticClient {
	private final AbstractSctlServer server;

	private final byte busId;
	private int tagPart = 0;

	public SctlSyntheticClient(AbstractSctlServer server, byte busId) {
		this.server = server;
		this.busId = busId;
	}

	/**
	 * Generate a tag for the synthesized client
	 * 
	 * @return
	 */
	public int tag() {
		int tag = (busId << 24) | tagPart;
		tagPart++;
		tagPart %= 0x00ffffff;
		return tag;
	}

	/**
	 * Synthesize an attach command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param pid the PID of the target process
	 * @param ctlid the CTLID for the response
	 * @param ctx the context for the response
	 */
	public void synthAttach(AsyncLock.Hold hold, long pid, long ctlid, String platform,
			AbstractSctlContext ctx) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		server.broadcast(hold, dialect.createSel(tag, new SctlAttachRequest(pid)), null);
		AbstractSctlAttachReply reply = dialect.create(AbstractSctlAttachReply.class);
		reply.ctlid = ctlid;
		reply.ctx = ctx;
		if (reply.supportsPlatform()) {
			reply.setPlatform(platform);
		}
		server.broadcast(hold, dialect.createSel(tag, reply), null);
	}

	/**
	 * Synthesize a detach command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 */
	public void synthDetach(AsyncLock.Hold hold, long ctlid) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		server.broadcast(hold, dialect.createSel(tag, new SctlDetachRequest(ctlid)), null);
		server.broadcast(hold, dialect.createSel(tag, new SctlDetachReply()), null);
	}

	/**
	 * Synthesize a continue command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 */
	public void synthContinue(AsyncLock.Hold hold, long ctlid) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		server.broadcast(hold, dialect.createSel(tag, new SctlContinueRequest(ctlid)), null);
		server.broadcast(hold, dialect.createSel(tag, new SctlContinueReply()), null);
	}

	/**
	 * Synthesize a stop command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 * @param ctx the context to include in the synthesized reply
	 */
	public void synthStop(AsyncLock.Hold hold, long ctlid, AbstractSctlContext ctx) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		server.broadcast(hold, dialect.createSel(tag, new SctlStopRequest(ctlid)), null);
		server.broadcast(hold, dialect.createSel(tag, new SctlStopReply(ctx)), null);
	}

	/**
	 * Synthesize a kill command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 */
	public void synthKill(AsyncLock.Hold hold, long ctlid) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		server.broadcast(hold, dialect.createSel(tag, new SctlKillRequest(ctlid)), null);
		server.broadcast(hold, dialect.createSel(tag, new SctlKillReply()), null);
	}

	/**
	 * Synthesize a focus command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 */
	public void synthFocus(AsyncLock.Hold hold, int ctlid) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		server.broadcast(hold, dialect.createSel(tag, new SctlFocusRequest(ctlid)), null);
		server.broadcast(hold, dialect.createSel(tag, new SctlFocusReply()), null);
	}

	/**
	 * Synthesize a set trap command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 * @param spec the trap specification for the command
	 * @param trpid the TRPID for the response
	 */
	public void synthSetTrap(AsyncLock.Hold hold, long ctlid, AbstractSctlTrapSpec spec,
			long trpid) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		//Msg.debug(this, "Synthesizing set trap thread=" + threadId + ",trap=" + trapId);
		server.broadcast(hold, dialect.createSel(tag, new SctlSetTrapRequest(ctlid, spec)), null);
		server.broadcast(hold, dialect.createSel(tag, new SctlSetTrapReply(trpid)), null);
	}

	/**
	 * Synthesize a clear trap command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param ctlid the CTLID for the command
	 * @param trpid the TRPID for the command
	 */
	public void synthClearTrap(AsyncLock.Hold hold, long ctlid, long trpid) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		//Msg.debug(this, "Synthesizing clear trap thread=" + threadId + ",trap=" + trapId);
		server.broadcast(hold, dialect.createSel(tag, new SctlClearTrapRequest(ctlid, trpid)),
			null);
		server.broadcast(hold, dialect.createSel(tag, new SctlClearTrapReply()), null);
	}

	/**
	 * Synthesize a get children command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param path the tree path identifying the object
	 */
	// TODO: It'd be better to use an event than command synthesis here
	public void synthGetChildren(AsyncLock.Hold hold, List<String> path) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		//Msg.debug(this, "Synthesizing clear trap thread=" + threadId + ",trap=" + trapId);
		String joinedPath = StringUtils.join(path, SctlTargetObject.PATH_SEPARATOR_STRING);
		server.broadcast(hold, dialect.createSel(tag, new SctlGetElementsRequest(joinedPath)),
			null);
		server.broadcast(hold, dialect.createSel(tag, new SctlGetElementsReply()), null);
	}

	/**
	 * Synthesize a get attributes command
	 * 
	 * @param hold an optional hold for re-entry
	 * @param path the tree path identifying the object
	 */
	// TODO: It'd be better to use an event than command synthesis here
	public void synthGetAttributes(AsyncLock.Hold hold, List<String> path) {
		int tag = tag();
		SctlDialect dialect = server.getDialect();
		//Msg.debug(this, "Synthesizing clear trap thread=" + threadId + ",trap=" + trapId);
		String joinedPath = StringUtils.join(path, SctlTargetObject.PATH_SEPARATOR_STRING);
		server.broadcast(hold, dialect.createSel(tag, new SctlGetAttributesRequest(joinedPath)),
			null);
		server.broadcast(hold, dialect.createSel(tag, new SctlGetAttributesReply()), null);
	}
}
