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

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IModelKeyReference;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class ModelKeyReferenceImpl1 implements ModelKeyReferenceInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IModelKeyReference jnaData;

	public ModelKeyReferenceImpl1(IModelKeyReference jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public String getKeyName() {
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetKeyName(bref));
		BSTR bstr = bref.getValue();
		String keyName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return keyName;
	}

	@Override
	public ModelObject getOriginalObject() {
		PointerByReference ppOriginalObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetOriginalObject(ppOriginalObject));

		WrapIModelObject wrap = new WrapIModelObject(ppOriginalObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject getContextObject() {
		PointerByReference ppContainingObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetContextObject(ppContainingObject));

		WrapIModelObject wrap = new WrapIModelObject(ppContainingObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject getKey() {
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.GetKey(ppObject, ppMetadata));

		return ModelObjectImpl.getObjectWithMetadata(ppObject, ppMetadata);
	}

	@Override
	public ModelObject getKeyValue() {
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.GetKeyValue(ppObject, ppMetadata));

		return ModelObjectImpl.getObjectWithMetadata(ppObject, ppMetadata);
	}

	@Override
	public void setKey(ModelObject object, KeyStore metadata) {
		Pointer pObject = object.getPointer();
		Pointer pMetadata = metadata.getPointer();
		COMUtils.checkRC(jnaData.SetKey(pObject, pMetadata));
	}

	@Override
	public void setKeyValue(ModelObject object, KeyStore metadata) {
		Pointer pObject = object.getPointer();
		Pointer pMetadata = metadata.getPointer();
		COMUtils.checkRC(jnaData.SetKey(pObject, pMetadata));
	}

}
