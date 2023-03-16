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
import agent.dbgmodel.dbgmodel.debughost.DebugHostModule1;
import agent.dbgmodel.jna.dbgmodel.debughost.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostModuleInternal extends DebugHostModule1 {
	Map<Pointer, DebugHostModuleInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostModuleInternal instanceFor(WrapIDebugHostModule1 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostModuleImpl1::new);
	}

	static DebugHostModuleInternal instanceFor(WrapIDebugHostModule2 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostModuleImpl2::new);
	}

	List<Preferred<WrapIDebugHostModule1>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDebugHostModule2.IID_IDEBUG_HOST_MODULE2, WrapIDebugHostModule2.class),
		new Preferred<>(IDebugHostModule1.IID_IDEBUG_HOST_MODULE, WrapIDebugHostModule1.class));

	static DebugHostModuleInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugHostModuleInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
