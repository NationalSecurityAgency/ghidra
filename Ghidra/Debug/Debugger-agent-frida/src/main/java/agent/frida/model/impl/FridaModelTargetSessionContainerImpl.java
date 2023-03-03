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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.frida.manager.FridaCause;
import agent.frida.manager.FridaSession;
import agent.frida.model.iface2.FridaModelTargetRoot;
import agent.frida.model.iface2.FridaModelTargetSession;
import agent.frida.model.iface2.FridaModelTargetSessionContainer;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SessionContainer",
	elements = {
		@TargetElementType(type = FridaModelTargetSessionImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class FridaModelTargetSessionContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSessionContainer {

	public FridaModelTargetSessionContainerImpl(FridaModelTargetRoot root) {
		super(root.getModel(), root, "Sessions", "SessionContainer");

		getManager().addEventsListener(this);
	}

	@Override
	public void sessionAdded(FridaSession sess, FridaCause cause) {
		FridaModelTargetSession session = getTargetSession(sess);
		changeElements(List.of(), List.of(session), Map.of(), "Added");
	}

	@Override
	public void sessionReplaced(FridaSession sess, FridaCause cause) {
		FridaModelTargetSession session = getTargetSession(sess);
		changeElements(List.of(), List.of(session), Map.of(), "Replaced");
	}

	@Override
	public void sessionRemoved(String sessionId, FridaCause cause) {
		changeElements(List.of( //
			sessionId //
		), List.of(), Map.of(), "Removed");
	}

	@Override
	public synchronized FridaModelTargetSession getTargetSession(FridaSession session) {
		TargetObject targetObject = getMapObject(session);
		if (targetObject != null) {
			FridaModelTargetSession targetSession = (FridaModelTargetSession) targetObject;
			targetSession.setModelObject(session);
			return targetSession;
		}
		return new FridaModelTargetSessionImpl(this, session);
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
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
