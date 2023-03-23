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
import agent.dbgmodel.dbgmodel.debughost.DebugHostBase;
import agent.dbgmodel.jna.dbgmodel.debughost.X_IDebugHostBaseClass;
import agent.dbgmodel.jna.dbgmodel.debughost.X_WrapIDebugHostBaseClass;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostBaseClassInternal extends DebugHostBase {

	Map<Pointer, X_DebugHostBaseClassInternal> CACHE = new WeakValueHashMap<>();

	static X_DebugHostBaseClassInternal instanceFor(X_WrapIDebugHostBaseClass data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, X_DebugHostBaseClassImpl::new);
	}

	List<Preferred<X_WrapIDebugHostBaseClass>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(X_IDebugHostBaseClass.IID_IDEBUG_HOST_BASE_CLASS,
			X_WrapIDebugHostBaseClass.class));

	static X_DebugHostBaseClassInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(X_DebugHostBaseClassInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
