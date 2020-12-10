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

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgmodel.dbgmodel.concept.ComparableConcept;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil.InterfaceSupplier;
import agent.dbgmodel.jna.dbgmodel.concept.IComparableConcept;
import agent.dbgmodel.jna.dbgmodel.concept.WrapIComparableConcept;
import ghidra.util.datastruct.WeakValueHashMap;

public interface ComparableConceptInternal extends ComparableConcept {
	Map<Pointer, ComparableConceptInternal> CACHE = new WeakValueHashMap<>();

	static ComparableConceptInternal instanceFor(WrapIComparableConcept data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, ComparableConceptImpl::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIComparableConcept>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIComparableConcept>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IComparableConcept.IID_ICOMPARABLE_CONCEPT),
					WrapIComparableConcept.class) //
				.build();

	static ComparableConceptInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgModelUtil.tryPreferredInterfaces(ComparableConceptInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
