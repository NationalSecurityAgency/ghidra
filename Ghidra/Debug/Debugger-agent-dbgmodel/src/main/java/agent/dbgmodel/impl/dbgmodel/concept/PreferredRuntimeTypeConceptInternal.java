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
package agent.dbgmodel.impl.dbgmodel.concept;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgmodel.dbgmodel.concept.PreferredRuntimeTypeConcept;
import agent.dbgmodel.jna.dbgmodel.concept.IPreferredRuntimeTypeConcept;
import agent.dbgmodel.jna.dbgmodel.concept.WrapIPreferredRuntimeTypeConcept;
import ghidra.util.datastruct.WeakValueHashMap;

public interface PreferredRuntimeTypeConceptInternal extends PreferredRuntimeTypeConcept {
	Map<Pointer, PreferredRuntimeTypeConceptInternal> CACHE = new WeakValueHashMap<>();

	static PreferredRuntimeTypeConceptInternal instanceFor(WrapIPreferredRuntimeTypeConcept data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, PreferredRuntimeTypeConceptImpl::new);
	}

	List<Preferred<WrapIPreferredRuntimeTypeConcept>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IPreferredRuntimeTypeConcept.IID_IPREFERRED_RUNTIME_TYPE_CONCEPT,
			WrapIPreferredRuntimeTypeConcept.class));

	static PreferredRuntimeTypeConceptInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(PreferredRuntimeTypeConceptInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
