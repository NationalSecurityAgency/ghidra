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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IKeyStore;

public class KeyStoreImpl implements KeyStoreInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IKeyStore jnaData;

	public KeyStoreImpl(IKeyStore jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject getKey(WString key) {
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.GetKey(key, ppObject, ppMetadata));

		return ModelObjectImpl.getObjectWithMetadata(ppObject, ppMetadata);
	}

	@Override
	public void setKey(WString key, ModelObject object, KeyStore metadata) {
		Pointer pObject = object.getPointer();
		Pointer pMetadata = metadata.getPointer();
		COMUtils.checkRC(jnaData.SetKey(key, pObject, pMetadata));
	}

	@Override
	public ModelObject getKeyValue(WString key) {
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.GetKeyValue(key, ppObject, ppMetadata));

		return ModelObjectImpl.getObjectWithMetadata(ppObject, ppMetadata);
	}

	@Override
	public void setKeyValue(WString key, ModelObject object) {
		Pointer pObject = object.getPointer();
		COMUtils.checkRC(jnaData.SetKeyValue(key, pObject));
	}

	@Override
	public void clearKeys() {
		COMUtils.checkRC(jnaData.ClearKeys());
	}

}
