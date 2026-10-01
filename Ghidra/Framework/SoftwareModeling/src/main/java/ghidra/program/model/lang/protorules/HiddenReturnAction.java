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
package ghidra.program.model.lang.protorules;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.XmlPullParser;

/**
 *	Action that allocates a pointer, required for the output, from the input resources.
 */
public class HiddenReturnAction extends SharedAction {
	private ParamListStandard inputResource;	// Input parameter resources

	public HiddenReturnAction(PrototypeModel model) {
		super(model);
		ParamList inputs = model.getInputResource();
		this.inputResource = (ParamListStandard) inputs;
	}

	@Override
	public void applyBefore(PrototypePieces proto, DataTypeManager dtManager, boolean addAutoParams,
			ArrayList<ParameterPieces> params, int[] inputStatus, int[] outputStatus) {
		if (params.size() == 2) {	// Check for hidden parameters defined by the output list
			ParameterPieces last = params.get(params.size() - 1);
			if (last.hiddenReturnPtr) {
				// Need to pull from registers marked as hiddenret 
				inputResource.assignAddressFallback(StorageClass.HIDDENRET, last.type, false,
					inputStatus, last);
			}
			else {
				// Assign as a regular first input pointer parameter
				inputResource.assignAddress(last.type, proto, 0, dtManager, inputStatus, last);
			}
			last.hiddenReturnPtr = true;
		}
	}

	@Override
	public void applyAfter(PrototypePieces proto, DataTypeManager dtManager, boolean addAutoParams,
			ArrayList<ParameterPieces> params, int[] inputStatus, int[] outputStatus) {
		if (model.hasThisPointer() && addAutoParams && params.size() > 1) {
			int thisIndex = 1;
			if (params.get(1).hiddenReturnPtr && params.size() > 2) {
				if (inputResource.isThisBeforeRetPointer()) {
					// pointer has been bumped by auto-return-storage
					params.get(1).swapMarkup(params.get(2));	// must swap storage and position for slots 1 and 2
				}
				else {
					thisIndex = 2;
				}
			}
			params.get(thisIndex).isThisPointer = true;
		}
	}

	@Override
	public SharedAction clone(PrototypeModel newModel) {
		return new HiddenReturnAction(newModel);
	}

	@Override
	public boolean isEquivalent(SharedAction obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		return true;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		// Nothing to encode
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		// Nothing to restore
	}

}
