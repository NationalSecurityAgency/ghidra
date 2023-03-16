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
import agent.dbgmodel.dbgmodel.debughost.DebugHostEvaluator1;
import agent.dbgmodel.jna.dbgmodel.debughost.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostEvaluatorInternal extends DebugHostEvaluator1 {
	Map<Pointer, DebugHostEvaluatorInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostEvaluatorInternal instanceFor(WrapIDebugHostEvaluator1 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostEvaluatorImpl1::new);
	}

	static DebugHostEvaluatorInternal instanceFor(WrapIDebugHostEvaluator2 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugHostEvaluatorImpl2::new);
	}

	List<Preferred<WrapIDebugHostEvaluator1>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDebugHostEvaluator2.IID_IDEBUG_HOST_EVALUATOR2,
			WrapIDebugHostEvaluator2.class),
		new Preferred<>(IDebugHostEvaluator1.IID_IDEBUG_HOST_EVALUATOR,
			WrapIDebugHostEvaluator1.class));

	static DebugHostEvaluatorInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugHostEvaluatorInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
