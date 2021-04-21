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
package agent.dbgmodel.model.impl;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jdom.JDOMException;

import agent.dbgeng.manager.impl.*;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import agent.dbgeng.model.iface2.DbgModelTargetSession;
import agent.dbgmodel.manager.DbgManager2Impl;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.AbstractTargetObject;
import ghidra.dbg.agent.AbstractTargetObject.ProxyFactory;
import ghidra.dbg.agent.SpiTargetObject;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import utilities.util.ProxyUtilities;

public class DbgModel2Impl extends AbstractDbgModel
		implements ProxyFactory<List<Class<? extends TargetObject>>> {
	// TODO: Need some minimal memory modeling per architecture on the model/agent side.
	// The model must convert to and from Ghidra's address space names
	protected static final String SPACE_NAME = "ram";

	public static final XmlSchemaContext SCHEMA_CTX;
	public static final TargetObjectSchema ROOT_SCHEMA;
	static {
		try {
			//SCHEMA_CTX =
			//		XmlSchemaContext.deserialize(ResourceManager.getResourceAsStream("dbgmodel.xml"));
			SCHEMA_CTX = XmlSchemaContext
					.deserialize(DbgModel2Impl.class.getResourceAsStream("dbgmodel_schema.xml"));
			ROOT_SCHEMA = SCHEMA_CTX.getSchema(SCHEMA_CTX.name("Debugger"));
		}
		catch (IOException | JDOMException e) {
			throw new AssertionError(e);
		}
	}

	// Don't make this static, so each model has a unique "ram" space
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });

	protected final DbgManager2Impl dbg;
	protected DbgModelTargetSession session;

	protected Map<Object, TargetObject> objectMap = new HashMap<>();

	public DbgModel2Impl() {
		this.dbg = new DbgManager2Impl();
		//System.out.println(XmlSchemaContext.serialize(SCHEMA_CTX));
		this.root = new DbgModel2TargetRootImpl(this, ROOT_SCHEMA);
		this.completedRoot = CompletableFuture.completedFuture(root);
		addModelRoot(root);
	}

	@Override
	public SpiTargetObject createProxy(AbstractTargetObject<?> delegate,
			List<Class<? extends TargetObject>> mixins) {
		mixins.add(DbgModel2TargetProxy.class);
		return ProxyUtilities.composeOnDelegate(DbgModelTargetObject.class,
			(DbgModelTargetObject) delegate, mixins, DelegateDbgModel2TargetObject.LOOKUP);
	}

	@Override
	public String getBrief() {
		return "DBGMODEL@" + Integer.toHexString(System.identityHashCode(this));
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
		root.invalidateSubtree(root, "Dbgmodel is terminating");
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
		return dbg;
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
	public void addModelObject(Object object, TargetObject modelObject) {
		if (modelObject == null) {
			Msg.error(this, "Attempt to add null for key: " + object);
			return;
		}
		objectMap.put(object, modelObject);
		if (object instanceof DbgProcessImpl) {
			DbgProcessImpl impl = (DbgProcessImpl) object;
			objectMap.put(impl.getId(), modelObject);
		}
		if (object instanceof DbgThreadImpl) {
			DbgThreadImpl impl = (DbgThreadImpl) object;
			objectMap.put(impl.getId(), modelObject);
		}
	}

	@Override
	public TargetObject getModelObject(Object object) {
		return objectMap.get(object);
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
