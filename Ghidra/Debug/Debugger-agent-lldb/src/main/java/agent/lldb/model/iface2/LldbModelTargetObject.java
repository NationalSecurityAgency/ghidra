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
package agent.lldb.model.iface2;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.AbstractLldbModel;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.agent.SpiTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.util.datastruct.ListenerSet;

public interface LldbModelTargetObject extends SpiTargetObject {

	@Override
	public AbstractLldbModel getModel();

	public default CompletableFuture<Void> init(Map<String, Object> map) {
		return CompletableFuture.completedFuture(null);
	}

	public default LldbManagerImpl getManager() {
		return (LldbManagerImpl) getModel().getManager();
	}

	public default LldbManagerImpl getManagerWithCheck() {
		LldbManagerImpl impl = (LldbManagerImpl) getModel().getManager();
		if (impl == null) {
			return impl;
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

	public LldbModelTargetSession getParentSession();

	public LldbModelTargetProcess getParentProcess();

	public LldbModelTargetThread getParentThread();

	public TargetObject getProxy();

	public void setModified(Map<String, Object> map, boolean b);

	public void setModified(boolean modified);

	public void resetModified();

	public Object getModelObject();

	public void setModelObject(Object modelObject);

	public void addMapObject(Object object, TargetObject targetObject);

	public TargetObject getMapObject(Object object);

	public void deleteMapObject(Object object);
}
