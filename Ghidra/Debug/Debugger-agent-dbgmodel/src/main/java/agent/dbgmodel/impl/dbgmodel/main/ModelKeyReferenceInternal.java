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

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgmodel.dbgmodel.main.ModelKeyReference1;
import agent.dbgmodel.jna.dbgmodel.main.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface ModelKeyReferenceInternal extends ModelKeyReference1 {
	Map<Pointer, ModelKeyReferenceInternal> CACHE = new WeakValueHashMap<>();

	static ModelKeyReferenceInternal instanceFor(WrapIModelKeyReference1 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, ModelKeyReferenceImpl1::new);
	}

	static ModelKeyReferenceInternal instanceFor(WrapIModelKeyReference2 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, ModelKeyReferenceImpl2::new);
	}

	List<Preferred<WrapIModelKeyReference1>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IModelKeyReference2.IID_IMODEL_REFERENCE2, WrapIModelKeyReference2.class),
		new Preferred<>(IModelKeyReference.IID_IMODEL_REFERENCE, WrapIModelKeyReference1.class));

	static ModelKeyReferenceInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(ModelKeyReferenceInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
