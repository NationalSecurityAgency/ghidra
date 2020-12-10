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
package agent.dbgmodel.impl.dbgmodel.datamodel;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.datamodel.DataModelManager2;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectInternal;
import agent.dbgmodel.jna.dbgmodel.datamodel.IDataModelManager2;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class DataModelManagerImpl2 extends DataModelManagerImpl1 implements DataModelManager2 {
	@SuppressWarnings("unused")
	private final IDataModelManager2 jnaData;

	public DataModelManagerImpl2(IDataModelManager2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject acquireSubNamespace(WString modelName, WString subNamespaceModelName,
			WString accessName, KeyStore metadata) {
		Pointer pMetadata = metadata.getPointer();
		PointerByReference ppNamespaceModelObject = new PointerByReference();
		COMUtils.checkRC(jnaData.AcquireSubNamespace(modelName, subNamespaceModelName, accessName,
			pMetadata, ppNamespaceModelObject));

		WrapIModelObject wrap = new WrapIModelObject(ppNamespaceModelObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createTypedIntrinsicObjectEx(DebugHostContext context,
			VARIANT.ByReference intrinsicData, DebugHostType1 type) {
		Pointer pContext = context.getPointer();
		Pointer pType = type.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(
			jnaData.CreateTypedIntrinsicObjectEx(pContext, intrinsicData, pType, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

}
