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
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbolEnumerator;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostSymbolEnumerator;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostSymbolEnumerator;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostSymbolEnumeratorInternal extends DebugHostSymbolEnumerator {
	Map<Pointer, DebugHostSymbolEnumeratorInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostSymbolEnumeratorInternal instanceFor(WrapIDebugHostSymbolEnumerator data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostSymbolEnumeratorImpl::new);
	}

	List<Preferred<WrapIDebugHostSymbolEnumerator>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDebugHostSymbolEnumerator.IID_IDEBUG_HOST_SYMBOL_ENUMERATOR,
			WrapIDebugHostSymbolEnumerator.class));

	static DebugHostSymbolEnumeratorInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugHostSymbolEnumeratorInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
