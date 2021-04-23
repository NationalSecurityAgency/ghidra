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
package agent.dbgeng.model.iface2;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.AbstractDbgModel;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.agent.SpiTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.util.datastruct.ListenerSet;

public interface DbgModelTargetObject extends SpiTargetObject {

	@Override
	public AbstractDbgModel getModel();

	public default DbgManagerImpl getManager() {
		return (DbgManagerImpl) getModel().getManager();
	}

	public default CompletableFuture<Void> init(Map<String, Object> map) {
		return CompletableFuture.completedFuture(null);
	}

	public default DbgManagerImpl getManagerWithCheck() {
		DbgManagerImpl impl = (DbgManagerImpl) getModel().getManager();
		if (impl == null) {
			return impl;
		}
		DebugStatus status = impl.getControl().getExecutionStatus();
		if (status.equals(DebugStatus.GO)) {
			System.err.println("Attempt to access DbgManager while GO");
			throw new RuntimeException("Attempt to access DbgManager while GO");
		}
		return impl;
	}

	public Delta<?, ?> changeAttributes(List<String> remove, Map<String, ?> add, String reason);

	public CompletableFuture<? extends Map<String, ?>> requestNativeAttributes();

	public default CompletableFuture<Void> requestAugmentedAttributes() {
		return AsyncUtils.NIL;
	}

	public CompletableFuture<List<TargetObject>> requestNativeElements();

	public ListenerSet<DebuggerModelListener> getListeners();

	public DbgModelTargetSession getParentSession();

	public DbgModelTargetProcess getParentProcess();

	public DbgModelTargetThread getParentThread();

	public TargetObject getProxy();

	public void setModified(Map<String, Object> map, boolean b);

	public void setModified(boolean modified);

	public void resetModified();

}
