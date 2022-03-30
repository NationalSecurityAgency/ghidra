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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaManager;
import agent.frida.manager.impl.FridaManagerImpl;
import agent.frida.model.AbstractFridaModel;
import agent.frida.model.iface2.FridaModelTargetProcess;
import agent.frida.model.iface2.FridaModelTargetSession;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.DebuggerObjectModelWithMemory;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.*;

public class FridaModelImpl extends AbstractFridaModel implements DebuggerObjectModelWithMemory {
	// The model must convert to and from Ghidra's address space names
	protected static final String SPACE_NAME = "ram";

	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(FridaModelTargetRootImpl.class);

	// Don't make this static, so each model has a unique "Frida" space
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });

	protected FridaManager manager;
	protected FridaModelTargetSession session;

	protected final FridaModelTargetRootImpl root;
	protected final CompletableFuture<FridaModelTargetRootImpl> completedRoot;

	protected Map<Object, TargetObject> objectMap = new HashMap<>();

	public FridaModelImpl() {
		this.manager = FridaManager.newInstance();
		this.root = new FridaModelTargetRootImpl(this, ROOT_SCHEMA);
		this.completedRoot = CompletableFuture.completedFuture(root);
		addModelRoot(root);
	}

	@Override
	public String getBrief() {
		return "FRIDA@" + Integer.toHexString(System.identityHashCode(this));
	}

	@Override
	public AddressSpace getAddressSpace(String name) {
		if (!SPACE_NAME.equals(name)) {
			return null;
		}
		return space;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	@Override
	public CompletableFuture<Void> startFrida(String[] args) {
		return manager.start(args).thenApplyAsync(__ -> null, clientExecutor);
	}

	@Override
	public boolean isRunning() {
		return manager.isRunning();
	}

	@Override
	public void terminate() throws IOException {
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		root.invalidateSubtree(root, "Frida is terminating");
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
	public FridaManagerImpl getManager() {
		return (FridaManagerImpl) manager;
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
	public FridaModelTargetSession getSession() {
		return session;
	}

	@Override
	public TargetMemory getMemory(TargetObject target, Address address, int length) {
		if (target instanceof FridaModelTargetProcess) {
			FridaModelTargetProcess process = (FridaModelTargetProcess) target;
			return new FridaModelTargetMemoryContainerImpl(process);
		}
		return null;
	}

	@Override
	public void addModelObject(Object object, TargetObject targetObject) {
		if (object == null) {
			return;
		}
		objectMap.put(FridaClient.getModelKey(object), targetObject);
	}

	@Override
	public TargetObject getModelObject(Object object) {
		if (object == null) {
			return null;
		}
		return objectMap.get(FridaClient.getModelKey(object));
	}

	public void deleteModelObject(Object object) {
		if (object == null) {
			return;
		}
		objectMap.remove(FridaClient.getModelKey(object));
	}

	@Override
	public <T> CompletableFuture<T> gateFuture(CompletableFuture<T> future) {
		return super.gateFuture(future).exceptionally(ex -> {
			for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
				if (cause instanceof RejectedExecutionException) {
					throw new DebuggerModelTerminatingException("Frida is terminating", ex);
				}
			}
			return ExceptionUtils.rethrow(ex);
		});
	}

}
