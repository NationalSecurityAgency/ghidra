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
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgmodel.dbgmodel.main.ModelKeyReference2;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IModelKeyReference2;

public class ModelKeyReferenceImpl2 extends ModelKeyReferenceImpl1 implements ModelKeyReference2 {
	@SuppressWarnings("unused")
	private final IModelKeyReference2 jnaData;

	public ModelKeyReferenceImpl2(IModelKeyReference2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void overrideContextObject(ModelObject newContextObject) {
		Pointer pNewContextObject = newContextObject.getPointer();
		COMUtils.checkRC(jnaData.OverrideContextObject(pNewContextObject));
	}

}
