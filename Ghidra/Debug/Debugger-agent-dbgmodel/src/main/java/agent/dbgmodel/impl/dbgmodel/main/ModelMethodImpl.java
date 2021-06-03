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
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IModelMethod;

public class ModelMethodImpl implements ModelMethodInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IModelMethod jnaData;

	public ModelMethodImpl(IModelMethod jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject call(ModelObject contextObject, long argCount, Pointer[] ppArguments) {
		Pointer pContextObject = contextObject.getPointer();
		ULONGLONG ulArgCount = new ULONGLONG(argCount);

		PointerByReference ppResult = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(
			jnaData.Call(pContextObject, ulArgCount, ppArguments, ppResult, ppMetadata));

		return ModelObjectImpl.getObjectWithMetadata(ppResult, ppMetadata);
	}

}
