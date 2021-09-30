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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.AbstractLldbModel;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import agent.lldb.model.iface2.LldbModelTargetSession;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.DebuggerObjectModelWithMemory;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;

public class LldbModelImpl extends AbstractLldbModel implements DebuggerObjectModelWithMemory {
	// TODO: Need some minimal memory modeling per architecture on the model/agent side.
	// The model must convert to and from Ghidra's address space names
	protected static final String SPACE_NAME = "ram";

	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(LldbModelTargetRootImpl.class);

	// Don't make this static, so each model has a unique "LLDB" space
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });

	protected LldbManager manager;
	protected final LldbModelTargetRootImpl root;
	protected LldbModelTargetSession session;

	protected final CompletableFuture<LldbModelTargetRootImpl> completedRoot;

	protected Map<Object, TargetObject> objectMap = new HashMap<>();

	public LldbModelImpl() {
		this.manager = LldbManager.newInstance();
		//System.out.println(XmlSchemaContext.serialize(SCHEMA_CTX));
		this.root = new LldbModelTargetRootImpl(this, ROOT_SCHEMA);
		this.completedRoot = CompletableFuture.completedFuture(root);
		/*
		SBTarget s = manager.getSession(new DebugSessionId(0));
		LldbModelTargetSessionContainer sessions = root.sessions;
		this.session = sessions.getTargetSession(s);
		*/
		addModelRoot(root);
	}

	@Override
	public String getBrief() {
		return "LLDB@" + Integer.toHexString(System.identityHashCode(this));
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
	public CompletableFuture<Void> startLLDB(String[] args) {
		return manager.start(args).thenApplyAsync(__ -> null, clientExecutor);
	}

	@Override
	public boolean isRunning() {
		return manager.isRunning();
	}

	@Override
	public void terminate() throws IOException {
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		root.invalidateSubtree(root, "LLDB is terminating");
		manager.terminate();
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
	public LldbManagerImpl getManager() {
		return (LldbManagerImpl) manager;
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
	public LldbModelTargetSession getSession() {
		return session;
	}

	@Override
	public TargetMemory getMemory(TargetObject target, Address address, int length) {
		if (target instanceof LldbModelTargetProcess) {
			LldbModelTargetProcess process = (LldbModelTargetProcess) target;
			return new LldbModelTargetMemoryContainerImpl(process);
		}
		return null;
	}

	@Override
	public void addModelObject(Object object, TargetObject targetObject) {
		objectMap.put(DebugClient.getModelKey(object), targetObject);
	}

	@Override
	public TargetObject getModelObject(Object object) {
		return objectMap.get(DebugClient.getModelKey(object));
	}

	public void deleteModelObject(Object object) {
		objectMap.remove(DebugClient.getModelKey(object));
	}

	@Override
	public <T> CompletableFuture<T> gateFuture(CompletableFuture<T> future) {
		return super.gateFuture(future).exceptionally(ex -> {
			for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
				if (cause instanceof RejectedExecutionException) {
					throw new DebuggerModelTerminatingException("LLDB is terminating", ex);
				}
			}
			return ExceptionUtils.rethrow(ex);
		});
	}

}
