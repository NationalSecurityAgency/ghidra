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
package mdemangler.typeinfo;

import mdemangler.*;
import mdemangler.datatype.modifier.MDBasedAttribute;
import mdemangler.functiontype.MDFunctionType;

/**
 * This class represents a virtual call (Microsoft C++ mangling parlance)
 *  derivative of MDTypeInfo.
 */
public class MDVCall extends MDMemberFunctionInfo {

	private static final String NEAR_STRING = "__near ";
	private static final String FAR_STRING = "__far ";

	enum ThisModel {
		NEAR, FAR
	}

	enum CallModel {
		NEAR, FAR
	}

	enum VfptrModel {
		NEAR, FAR, BASED
	}

	private MDEncodedNumber callIndex;
	private char thunkType;
	private ThisModel myThisModel;
	private CallModel myCallModel;
	private VfptrModel myVfptrModel;
	private MDBasedAttribute basedType;

	public MDVCall(MDMang dmang) {
		super(dmang);
		MDFunctionType functionType = new MDFunctionType(dmang, false, false);
		mdtype = functionType;
		// TODO: consider what to do... from what I understand, this is
		// also "virtual" but "virtual" does not get printed.
		setThunk();
		callIndex = new MDEncodedNumber(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		// TODO: Future specialization on 16-bit or 32plus
		// dmang.appendString(builder, getNameModifier_32PlusBitModel());
		super.insert(builder);
	}

	public String getNameModifier_16BitModel() {
		String modifier = "{" + callIndex + ",";
		if (myThisModel == ThisModel.NEAR) {
			modifier += NEAR_STRING;
		}
		else {
			modifier += FAR_STRING;
		}
		modifier += "this, ";
		if (myCallModel == CallModel.NEAR) {
			modifier += NEAR_STRING;
		}
		else {
			modifier += FAR_STRING;
		}
		modifier += "call, ";
		if (myVfptrModel == VfptrModel.NEAR) {
			modifier += NEAR_STRING;
		}
		else if (myVfptrModel == VfptrModel.FAR) {
			modifier += FAR_STRING;
		}
		else {
			modifier += basedType; // TODO based value.
		}
		modifier += "vfptr}}' }'";
		return modifier;
	}

	public String getNameModifier_32PlusBitModel() {
		String modifier;
		if (myThisModel == ThisModel.NEAR && myCallModel == CallModel.NEAR &&
			myVfptrModel == VfptrModel.NEAR) {
			modifier = "{" + callIndex + "," + "{flat}}' }'";
		}
		else {
			modifier = ""; // TOOD: should throw exception?
		}
		return modifier;
	}

	@Override
	protected void parseInternal() throws MDException {
		callIndex.parse();
		thunkType = dmang.getAndIncrement();
		switch (thunkType) { // TODO 20171113: Need tests for all of these.
			case 'A': // UINFO: near 'this', near 'call', near 'vfptr'
				myThisModel = ThisModel.NEAR;
				myCallModel = CallModel.NEAR;
				myVfptrModel = VfptrModel.NEAR;
				// nameModifier += "{flat}}' }'"; //"{flat}" is valid for 32-bit,
				// but not others
				// nameModifier += "__near this, __near call, __near vfptr}}' }'";
				break;
			case 'B': // UINFO: near 'this', far 'call', near 'vfptr'
				myThisModel = ThisModel.NEAR;
				myCallModel = CallModel.FAR;
				myVfptrModel = VfptrModel.NEAR;
				// nameModifier += "__near this, __far call, __near vfptr}}' }'";
				break;
			case 'C': // UINFO: far 'this', near 'call', near 'vfptr'
				myThisModel = ThisModel.FAR;
				myCallModel = CallModel.NEAR;
				myVfptrModel = VfptrModel.NEAR;
				// nameModifier += "__far this, __near call, __near vfptr}}' }'";
				break;
			case 'D': // UINFO: far 'this', far 'call', near 'vfptr'
				myThisModel = ThisModel.FAR;
				myCallModel = CallModel.FAR;
				myVfptrModel = VfptrModel.NEAR;
				// nameModifier += "__far this, __far call, __near vfptr}}' }'";
				break;
			case 'E': // UINFO: near 'this', near 'call', far 'vfptr'
				myThisModel = ThisModel.NEAR;
				myCallModel = CallModel.NEAR;
				myVfptrModel = VfptrModel.FAR;
				// nameModifier += "__near this, __near call, __far vfptr}}' }'";
				break;
			case 'F': // UINFO: near 'this', far 'call', far 'vfptr'
				myThisModel = ThisModel.NEAR;
				myCallModel = CallModel.FAR;
				myVfptrModel = VfptrModel.FAR;
				// nameModifier += "__near this, __far call, __far vfptr}}' }'";
				break;
			case 'G': // UINFO: far 'this', near 'call', far 'vfptr'
				myThisModel = ThisModel.FAR;
				myCallModel = CallModel.NEAR;
				myVfptrModel = VfptrModel.FAR;
				// nameModifier += "__far this, __near call, __far vfptr}}' }'";
				break;
			case 'H': // UINFO: far 'this', far 'call', far 'vfptr'
				myThisModel = ThisModel.FAR;
				myCallModel = CallModel.FAR;
				myVfptrModel = VfptrModel.FAR;
				// nameModifier += "__far this, __far call, __far vfptr}}' }'";
				break;
			case 'I': // UINFO: near 'this', near 'call', based 'vfptr'
				myThisModel = ThisModel.NEAR;
				myCallModel = CallModel.NEAR;
				myVfptrModel = VfptrModel.BASED;
				basedType.parse(); // TODO: check this
				// nameModifier += "__near this, __near call, " + basedType + "
				// vfptr}}' }'";
				break;
			case 'J': // UINFO: near 'this', far 'call', based 'vfptr'
				myThisModel = ThisModel.NEAR;
				myCallModel = CallModel.FAR;
				myVfptrModel = VfptrModel.BASED;
				basedType.parse(); // TODO: check this
				// nameModifier += "__near this, __far call, " + basedType + "
				// vfptr}}' }'";
				break;
			case 'K': // UINFO: far 'this', near 'call', based 'vfptr'
				myThisModel = ThisModel.FAR;
				myCallModel = CallModel.NEAR;
				myVfptrModel = VfptrModel.BASED;
				basedType.parse(); // TODO: check this
				// nameModifier += "__far this, __near call, " + basedType + "
				// vfptr}}' }'";
				break;
			case 'L': // UINFO: far 'this', far 'call', based 'vfptr'
				myThisModel = ThisModel.FAR;
				myCallModel = CallModel.FAR;
				myVfptrModel = VfptrModel.BASED;
				basedType.parse(); // TODO: check this
				// nameModifier += "__far this, __far call, " + basedType + "
				// vfptr}}' }'";
				break;
			default:
				throw new MDException("VCall ($B), unexpected thunkType: " + thunkType);
		}
		// TODO evaluate whether parseInternal() or parse.
		super.parseInternal();
		// TODO: Future specialization on 16-bit or 32plus
		nameModifier = getNameModifier_32PlusBitModel();
	}
}

/******************************************************************************/
/******************************************************************************/
