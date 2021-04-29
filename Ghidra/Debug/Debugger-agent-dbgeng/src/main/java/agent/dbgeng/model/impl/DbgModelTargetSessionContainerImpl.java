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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgSession;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(name = "SessionContainer", elements = {
	@TargetElementType(type = DbgModelTargetSessionImpl.class) }, attributes = {
		@TargetAttributeType(type = Void.class) }, canonicalContainer = true)
public class DbgModelTargetSessionContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetSessionContainer {

	public DbgModelTargetSessionContainerImpl(DbgModelTargetRoot root) {
		super(root.getModel(), root, "Sessions", "SessionContainer");

		getManager().addEventsListener(this);
	}

	@Override
	public void sessionAdded(DbgSession sess, DbgCause cause) {
		DbgModelTargetSession session = getTargetSession(sess);
		changeElements(List.of(), List.of(session), Map.of(), "Added");
	}

	@Override
	public void sessionRemoved(DebugSessionId sessionId, DbgCause cause) {
		//synchronized (this) {
		//	sessionsById.remove(sessionId);
		//}
		changeElements(List.of( //
			DbgModelTargetSessionImpl.indexSession(sessionId) //
		), List.of(), Map.of(), "Removed");
	}

	@Override
	public synchronized DbgModelTargetSession getTargetSession(DbgSession session) {
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(session);
		if (modelObject != null) {
			return (DbgModelTargetSession) modelObject;
		}
		return new DbgModelTargetSessionImpl(this, session);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return CompletableFuture.completedFuture(null);
		/*
		DbgManagerImpl manager = getManager();
		if (manager.checkAccessProhibited()) {
			return CompletableFuture.completedFuture(this.elementsView);
		}
		return manager.listSessions().thenApply(byIID -> {
			List<TargetObject> sessions;
			synchronized (this) {
				sessions = byIID.values()
						.stream()
					.map(this::getTargetSession)
						.collect(Collectors.toList());
			}
			setElements(sessions, "Refreshed");
			return this.elementsView;
		});
		*/
	}

}
