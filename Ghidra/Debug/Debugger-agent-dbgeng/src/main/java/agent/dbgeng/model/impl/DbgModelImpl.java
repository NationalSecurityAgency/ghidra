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
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgSessionImpl;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.iface2.DbgModelTargetSession;
import agent.dbgeng.model.iface2.DbgModelTargetSessionContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.*;

public class DbgModelImpl extends AbstractDbgModel {
	// TODO: Need some minimal memory modeling per architecture on the model/agent side.
	// The model must convert to and from Ghidra's address space names
	protected static final String SPACE_NAME = "ram";

	// Don't make this static, so each model has a unique "GDB" space
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });

	protected final DbgManager dbg;
	protected final DbgModelTargetRootImpl root;
	protected final DbgModelTargetSessionImpl session;

	protected final CompletableFuture<DbgModelTargetRootImpl> completedRoot;

	public DbgModelImpl() {
		this.dbg = DbgManager.newInstance();
		this.root = new DbgModelTargetRootImpl(this);
		this.completedRoot = CompletableFuture.completedFuture(root);
		DbgSessionImpl s = new DbgSessionImpl((DbgManagerImpl) dbg, new DebugSessionId(0));
		s.add();
		DbgModelTargetSessionContainer sessions = root.sessions;
		this.session = (DbgModelTargetSessionImpl) sessions.getTargetSession(s);
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
		return dbg.start(args);
	}

	@Override
	public boolean isRunning() {
		return dbg.isRunning();
	}

	@Override
	public void terminate() throws IOException {
		dbg.terminate();
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
			return CompletableFuture.completedFuture(null);
		}
		catch (Throwable t) {
			return CompletableFuture.failedFuture(t);
		}
	}

	@Override
	public DbgModelTargetSession getSession() {
		return session;
	}
}
