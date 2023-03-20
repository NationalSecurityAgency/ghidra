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
package agent.dbgmodel.impl.dbgmodel.debughost;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostContext;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostContext;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostContextInternal extends DebugHostContext {
	Map<Pointer, DebugHostContextInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostContextInternal instanceFor(WrapIDebugHostContext data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostContextImpl::new);
	}

	List<Preferred<WrapIDebugHostContext>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDebugHostContext.IID_IDEBUG_HOST_CONTEXT,
			WrapIDebugHostContext.class));

	static DebugHostContextInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugHostContextInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
