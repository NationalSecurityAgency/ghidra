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
import agent.dbgmodel.dbgmodel.debughost.DebugHostMemory1;
import agent.dbgmodel.jna.dbgmodel.debughost.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostMemoryInternal extends DebugHostMemory1 {
	Map<Pointer, DebugHostMemoryInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostMemoryInternal instanceFor(WrapIDebugHostMemory1 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostMemoryImpl1::new);
	}

	static DebugHostMemoryInternal instanceFor(WrapIDebugHostMemory2 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostMemoryImpl2::new);
	}

	List<Preferred<WrapIDebugHostMemory1>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDebugHostMemory2.IID_IDEBUG_HOST_MEMORY2, WrapIDebugHostMemory2.class),
		new Preferred<>(IDebugHostMemory1.IID_IDEBUG_HOST_MEMORY, WrapIDebugHostMemory1.class));

	static DebugHostMemoryInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugHostMemoryInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
