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
package agent.dbgmodel.impl.dbgmodel.datamodel.script;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.*;
import agent.dbgmodel.impl.dbgmodel.main.*;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelNameBinder;
import agent.dbgmodel.jna.dbgmodel.main.*;

public class DataModelNameBinderImpl implements DataModelNameBinderInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelNameBinder jnaData;

	private ModelObject value;
	private KeyStore metadata;
	private ModelObject reference;

	public DataModelNameBinderImpl(IDataModelNameBinder jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void bindValue(ModelObject contextObject, WString name) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppValue = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.BindValue(pContextObject, name, ppValue, ppMetadata));

		WrapIModelObject wrap0 = new WrapIModelObject(ppMetadata.getValue());
		try {
			value = ModelObjectInternal.tryPreferredInterfaces(wrap0::QueryInterface);
		}
		finally {
			wrap0.Release();
		}
		WrapIKeyStore wrap1 = new WrapIKeyStore(ppMetadata.getValue());
		try {
			metadata = KeyStoreInternal.tryPreferredInterfaces(wrap1::QueryInterface);
		}
		finally {
			wrap1.Release();
		}
	}

	@Override
	public void bindReference(ModelObject contextObject, WString name) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppReference = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.BindReference(pContextObject, name, ppReference, ppMetadata));

		WrapIModelObject wrap0 = new WrapIModelObject(ppMetadata.getValue());
		try {
			reference = ModelObjectInternal.tryPreferredInterfaces(wrap0::QueryInterface);
		}
		finally {
			wrap0.Release();
		}
		WrapIKeyStore wrap1 = new WrapIKeyStore(ppMetadata.getValue());
		try {
			metadata = KeyStoreInternal.tryPreferredInterfaces(wrap1::QueryInterface);
		}
		finally {
			wrap1.Release();
		}
	}

	@Override
	public KeyEnumerator enumerateValues(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateValues(pContextObject, ppEnumerator));

		WrapIKeyEnumerator wrap = new WrapIKeyEnumerator(ppEnumerator.getValue());
		try {
			return KeyEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public KeyEnumerator enumerateReferences(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateReferences(pContextObject, ppEnumerator));

		WrapIKeyEnumerator wrap = new WrapIKeyEnumerator(ppEnumerator.getValue());
		try {
			return KeyEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public ModelObject getValue() {
		return value;
	}

	public KeyStore getMetadata() {
		return metadata;
	}

	public ModelObject getReference() {
		return reference;
	}
}
