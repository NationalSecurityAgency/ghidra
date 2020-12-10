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
package agent.dbgmodel.impl.dbgmodel.main;

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgmodel.dbgmodel.main.ModelKeyReference1;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil.InterfaceSupplier;
import agent.dbgmodel.jna.dbgmodel.main.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface ModelKeyReferenceInternal extends ModelKeyReference1 {
	Map<Pointer, ModelKeyReferenceInternal> CACHE = new WeakValueHashMap<>();

	static ModelKeyReferenceInternal instanceFor(WrapIModelKeyReference1 data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, ModelKeyReferenceImpl1::new);
	}

	static ModelKeyReferenceInternal instanceFor(WrapIModelKeyReference2 data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, ModelKeyReferenceImpl2::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIModelKeyReference1>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIModelKeyReference1>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IModelKeyReference2.IID_IMODEL_REFERENCE2),
					WrapIModelKeyReference2.class) //
				.put(new REFIID(IModelKeyReference.IID_IMODEL_REFERENCE),
					WrapIModelKeyReference1.class) //
				.build();

	static ModelKeyReferenceInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgModelUtil.tryPreferredInterfaces(ModelKeyReferenceInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
