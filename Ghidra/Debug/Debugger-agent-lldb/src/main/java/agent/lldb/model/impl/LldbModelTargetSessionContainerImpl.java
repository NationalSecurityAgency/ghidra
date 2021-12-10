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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBTarget;
import agent.lldb.manager.LldbCause;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "SessionContainer",
	elements = {
		@TargetElementType(type = LldbModelTargetSessionImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetSessionContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSessionContainer {

	public LldbModelTargetSessionContainerImpl(LldbModelTargetRoot root) {
		super(root.getModel(), root, "Sessions", "SessionContainer");

		getManager().addEventsListener(this);
	}

	@Override
	public void sessionAdded(SBTarget sess, LldbCause cause) {
		LldbModelTargetSession session = getTargetSession(sess);
		changeElements(List.of(), List.of(session), Map.of(), "Added");
	}

	@Override
	public void sessionReplaced(SBTarget sess, LldbCause cause) {
		LldbModelTargetSession session = getTargetSession(sess);
		changeElements(List.of(), List.of(session), Map.of(), "Replaced");
	}

	@Override
	public void sessionRemoved(String sessionId, LldbCause cause) {
		changeElements(List.of( //
			sessionId //
		), List.of(), Map.of(), "Removed");
	}

	@Override
	public synchronized LldbModelTargetSession getTargetSession(SBTarget session) {
		TargetObject targetObject = getMapObject(session);
		if (targetObject != null) {
			LldbModelTargetSession targetSession = (LldbModelTargetSession) targetObject;
			targetSession.setModelObject(session);
			return targetSession;
		}
		return new LldbModelTargetSessionImpl(this, session);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listSessions().thenAccept(byIID -> {
			List<TargetObject> sessions;
			synchronized (this) {
				sessions = byIID.values()
						.stream()
						.map(this::getTargetSession)
						.collect(Collectors.toList());
			}
			setElements(sessions, "Refreshed");
		});
	}

}
