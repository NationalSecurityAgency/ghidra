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
import agent.dbgmodel.dbgmodel.concept.StringDisplayableConcept;
import agent.dbgmodel.jna.dbgmodel.concept.IStringDisplayableConcept;
import agent.dbgmodel.jna.dbgmodel.concept.WrapIStringDisplayableConcept;
import ghidra.util.datastruct.WeakValueHashMap;

public interface StringDisplayableConceptInternal extends StringDisplayableConcept {
	Map<Pointer, StringDisplayableConceptInternal> CACHE = new WeakValueHashMap<>();

	static StringDisplayableConceptInternal instanceFor(WrapIStringDisplayableConcept data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, StringDisplayableConceptImpl::new);
	}

	List<Preferred<WrapIStringDisplayableConcept>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IStringDisplayableConcept.IID_ISTRING_DISPLAYABLE_CONCEPT,
			WrapIStringDisplayableConcept.class));

	static StringDisplayableConceptInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(StringDisplayableConceptInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
