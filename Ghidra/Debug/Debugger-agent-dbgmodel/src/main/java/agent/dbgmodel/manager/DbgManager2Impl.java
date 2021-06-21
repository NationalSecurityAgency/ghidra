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
package agent.dbgmodel.manager;

import static ghidra.async.AsyncUtils.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.manager.DbgCause.Causes;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.gadp.impl.DbgModelClientThreadExecutor;
import agent.dbgmodel.gadp.impl.WrappedDbgModel;
import agent.dbgmodel.jna.cmd.*;
import agent.dbgmodel.model.impl.DbgModel2TargetObjectImpl;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.util.Msg;

public class DbgManager2Impl extends DbgManagerImpl {

	private DebugClient client;
	private WrappedDbgModel dbgmodel;

	/**
	 * Instantiate a new manager
	 */
	public DbgManager2Impl() {
		super();
	}

	public WrappedDbgModel getAccess() {
		return dbgmodel;
	}

	@Override
	public DebugClient getClient() {
		return client;
	}

	@Override
	public CompletableFuture<Void> start(String[] args) {
		state.set(DbgState.STARTING, Causes.UNCLAIMED);
		boolean create = true;
		if (args.length == 0) {
			engThread = new DbgModelClientThreadExecutor(() -> DbgModel.debugCreate());
		}
		else {
			String remoteOptions = String.join(" ", args);
			engThread =
				new DbgModelClientThreadExecutor(() -> DbgModel.debugConnect(remoteOptions));
			create = false;
		}
		engThread.setManager(this);
		AtomicReference<Boolean> creat = new AtomicReference<>(create);
		return sequence(TypeSpec.VOID).then(engThread, (seq) -> {
			doExecute(creat.get());
			seq.exit();
		}).finish().exceptionally((exc) -> {
			Msg.error(this, "start failed");
			return null;
		});
	}

	@Override
	protected void doExecute(Boolean create) {
		dbgmodel = ((DbgModelClientThreadExecutor) engThread).getAccess();
		reentrantClient = dbgmodel.getClient();
		client = super.getClient();
		super.doExecute(create);
	}

	public CompletableFuture<List<TargetObject>> listElements(List<String> path,
			DbgModel2TargetObjectImpl targetObject) {
		return execute(new DbgListElementsCommand(this, path, targetObject));
	}

	public CompletableFuture<? extends Map<String, ?>> listAttributes(List<String> path,
			DbgModel2TargetObjectImpl targetObject) {
		return execute(new DbgListAttributesCommand(this, path, targetObject));
	}

	public CompletableFuture<? extends TargetObject> applyMethods(List<String> path,
			DbgModel2TargetObjectImpl targetObject) {
		return execute(new DbgApplyMethodsCommand(this, path, targetObject));
	}

	public CompletableFuture<? extends Map<String, ?>> getRegisterMap(List<String> path) {
		return execute(new DbgGetRegisterMapCommand(this, path));
	}

	/*
	@Override
	public DbgSessionImpl getCurrentSession() {
		ModelObject currentSession = dbgmodel.getUtil().getCurrentSession();
		ModelObject keyValue = currentSession.getKeyValue("Id");
		Object val = keyValue.getValue();
		DebugSessionId sid = new DebugSessionId((Integer) val);
		curSession = getSessionComputeIfAbsent(sid);
		return curSession;
	}
	
	@Override
	public DbgProcessImpl getCurrentProcess() {
		synchronized (processes) {
			DebugProcessId id = getSystemObjects().getCurrentProcessId();
			return processes.get(id);
		}
	}
	
	@Override
	public DbgThreadImpl getCurrentThread() {
		synchronized (threads) {
			DebugThreadId id = getSystemObjects().getCurrentThreadId();
			return threads.get(id);
		}
	}
	*/

}
