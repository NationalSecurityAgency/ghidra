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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgSessionImpl;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.DebuggerObjectModelWithMemory;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.*;

public class DbgModelImpl extends AbstractDbgModel implements DebuggerObjectModelWithMemory {
	// TODO: Need some minimal memory modeling per architecture on the model/agent side.
	// The model must convert to and from Ghidra's address space names
	protected static final String SPACE_NAME = "ram";

	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(DbgModelTargetRootImpl.class);

	// Don't make this static, so each model has a unique "GDB" space
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });

	protected final DbgManager dbg;
	protected final DbgModelTargetRootImpl root;
	protected final DbgModelTargetSessionImpl session;

	protected final CompletableFuture<DbgModelTargetRootImpl> completedRoot;

	protected Map<Object, TargetObject> objectMap = new HashMap<>();

	public DbgModelImpl() {
		this.dbg = DbgManager.newInstance();
		//System.out.println(XmlSchemaContext.serialize(SCHEMA_CTX));
		this.root = new DbgModelTargetRootImpl(this, ROOT_SCHEMA);
		this.completedRoot = CompletableFuture.completedFuture(root);
		DbgSessionImpl s = new DbgSessionImpl((DbgManagerImpl) dbg, new DebugSessionId(0));
		s.add();
		DbgModelTargetSessionContainer sessions = root.sessions;
		this.session = (DbgModelTargetSessionImpl) sessions.getTargetSession(s);
		addModelRoot(root);
	}

	@Override
	public String getBrief() {
		return "DBGENG@" + Integer.toHexString(System.identityHashCode(this));
	}

	@Override
	public AddressSpace getAddressSpace(String name) {
		if (!SPACE_NAME.equals(name)) {
			return null;
		}
		return space;
	}

	// TODO: Place make this a model method?
	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	@Override
	public CompletableFuture<Void> startDbgEng(String[] args) {
		return dbg.start(args).thenApplyAsync(__ -> null, clientExecutor);
	}

	@Override
	public boolean isRunning() {
		return dbg.isRunning();
	}

	@Override
	public void terminate() throws IOException {
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		root.invalidateSubtree(root, "Dbgeng is terminating");
		dbg.terminate();
	}

	@Override
	public TargetObjectSchema getRootSchema() {
		return root.getSchema();
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return completedRoot;
	}

	@Override
	public DbgManagerImpl getManager() {
		return (DbgManagerImpl) dbg;
	}

	@Override
	public CompletableFuture<Void> close() {
		try {
			terminate();
			return super.close();
		}
		catch (RejectedExecutionException e) {
			reportError(this, "Model is already closing", e);
			return AsyncUtils.NIL;
		}
		catch (Throwable t) {
			return CompletableFuture.failedFuture(t);
		}
	}

	@Override
	public DbgModelTargetSession getSession() {
		return session;
	}

	@Override
	public TargetMemory getMemory(TargetObject target, Address address, int length) {
		if (target instanceof DbgModelTargetProcess) {
			DbgModelTargetProcess process = (DbgModelTargetProcess) target;
			return new DbgModelTargetMemoryContainerImpl(process);
		}
		return null;
	}

	@Override
	public void addModelObject(Object object, TargetObject targetObject) {
		objectMap.put(object, targetObject);
	}

	@Override
	public TargetObject getModelObject(Object object) {
		return objectMap.get(object);
	}

	@Override
	public void deleteModelObject(Object object) {
		objectMap.remove(object);
	}

	@Override
	public <T> CompletableFuture<T> gateFuture(CompletableFuture<T> future) {
		return super.gateFuture(future).exceptionally(ex -> {
			for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
				if (cause instanceof RejectedExecutionException) {
					throw new DebuggerModelTerminatingException("dbgeng is terminating", ex);
				}
			}
			return ExceptionUtils.rethrow(ex);
		});
	}
}
