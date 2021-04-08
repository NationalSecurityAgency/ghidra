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
import agent.dbgeng.model.iface1.DbgModelTargetInterpreter;
import agent.dbgeng.model.iface2.DbgModelTargetProcessContainer;
import agent.dbgeng.model.iface2.DbgModelTargetSession;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Session",
	elements = {
		@TargetElementType(type = Void.class) },
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
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetSessionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetSession {

	protected static final String DBG_PROMPT = "(kd)";
	private Integer base = 16;

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
		this.getModel().addModelObject(session, this);

		this.attributes = new DbgModelTargetSessionAttributesImpl(this);
		this.processes = new DbgModelTargetProcessContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			attributes, //
			processes //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			PROMPT_ATTRIBUTE_NAME, DbgModelTargetInterpreter.DBG_PROMPT, //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public CompletableFuture<Void> setActive() {
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
