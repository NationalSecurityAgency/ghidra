/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app;

import ghidra.program.util.ProgramLocation;

/**
 * 
 */
public interface GhidraLocationGenerator {
	void generateLocations(LocationCallback callback);
	
	ProgramLocation[] getAddressLocations();
	ProgramLocation[] getBytesLocations();
	ProgramLocation[] getCodeUnitLocations();
	ProgramLocation[] getCommentFieldLocations();
	ProgramLocation[] getPreCommentLocations();
	ProgramLocation[] getEolCommentLocations();
	ProgramLocation[] getPostCommentLocations();
	ProgramLocation[] getPlateCommentLocations();
	ProgramLocation[] getDividerLocations();
	ProgramLocation[] getFieldNameLocations();
	ProgramLocation[] getFunctionCommentLocations();
	ProgramLocation[] getFunctionSignatureLocations(); 
	ProgramLocation[] getIndentLocations();
	ProgramLocation[] getLabelLocations();
	ProgramLocation[] getMnemonicLocations();
	ProgramLocation[] getOperandLocations();
	ProgramLocation[] getOperandScalarLocations();
	ProgramLocation[] getOperandLabelLocations();
	ProgramLocation[] getFieldNameFieldLocations();
	ProgramLocation[] getProgramLocations();
	ProgramLocation[] getRegisterVarCommentLocations();
	ProgramLocation[] getRegisterVarDescriptionLocations();
	ProgramLocation[] getRegisterVarLocations();
	ProgramLocation[] getRegisterVarNameLocations();
	ProgramLocation[] getRegisterVarTypeLocations();
	ProgramLocation[] getSpaceLocations();
	ProgramLocation[] getSpacerLocations();
	ProgramLocation[] getStackVarCommentLocations();
	ProgramLocation[] getStackVarLocations();
	ProgramLocation[] getStackVarNameLocations();
	ProgramLocation[] getStackVarOffsetLocations();
	ProgramLocation[] getStackVarTypeLocations();
	ProgramLocation[] getStackVarXrefLocations();
	ProgramLocation[] getSubDataLocations();
	ProgramLocation[] getXrefLocations();

	ProgramLocation[] getLocationsWithNoLabels();
	ProgramLocation[] getLocationsWithDefaultLabel();
	ProgramLocation[] getLocationsWithNonDefaultLabel();
	ProgramLocation[] getLocationsWithMultipleLabels(); 
	ProgramLocation[] getLocationsWithInstructions();
	ProgramLocation[] getLocationsWithLocalLabels();
}
