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
import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface2.DbgModelTargetProcessContainer;
import agent.dbgeng.model.iface2.DbgModelTargetSession;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Session",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Attributes",
			type = DbgModelTargetSessionAttributesImpl.class,
			fixed = true),
		@TargetAttributeType(
			name = "Processes",
			type = DbgModelTargetProcessContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	})
public class DbgModelTargetSessionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetSession {

	protected static final String DBG_PROMPT = "(kd)";
	// NB: This should almost certainly always be implemented by the root of the object tree

	protected static String indexSession(DebugSessionId debugSystemId) {
		return PathUtils.makeIndex(debugSystemId.id);
	}

	protected static String indexSession(DbgSession session) {
		return indexSession(session.getId());
	}

	protected static String keySession(DbgSession session) {
		return PathUtils.makeKey(indexSession(session));
	}

	protected final DbgModelTargetSessionAttributesImpl attributes;
	protected final DbgModelTargetProcessContainerImpl processes;
	private DbgModelSelectableObject focus;

	protected String debugger = "kd"; // Used by DbgModelTargetEnvironment

	public DbgModelTargetSessionImpl(DbgModelTargetSessionContainerImpl sessions,
			DbgSession session) {
		super(sessions.getModel(), sessions, keySession(session), "Session");

		this.attributes = new DbgModelTargetSessionAttributesImpl(this);
		this.processes = new DbgModelTargetProcessContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			attributes, //
			processes //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, true, //
			PROMPT_ATTRIBUTE_NAME, DBG_PROMPT, //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public CompletableFuture<Void> select() {
		//DbgManagerImpl manager = getManager();
		//DbgProcessImpl process = manager.getCurrentProcess();
		//return manager.execute(new DbgProcessSelectCommand(manager, process));
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public DbgModelTargetProcessContainer getProcesses() {
		return processes;
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		TargetExecutionState targetState = convertState(state);
		setExecutionState(targetState, "ThreadStateChanged");
	}

}
