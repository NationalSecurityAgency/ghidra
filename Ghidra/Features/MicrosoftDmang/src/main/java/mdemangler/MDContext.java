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
package mdemangler;

import java.util.ArrayList;
import java.util.List;

import mdemangler.datatype.MDDataType;

/**
 * This class holds a single context that is pushed or popped to/from a context stack in MDMang.
 * A context contains "backreferences" (as we currently understand backreferences and a context
 * of them--simplified from more complicated contexts, we are trying to whittle this away toward
 * non-existence).  There are backrefNames, backrefParameters, and backrefTemplateParameters.  A
 * context is created from a previous context using particular rules that are dictated by an
 * enumerated MDMcontext annotation.  These, too, might go away, but we have boiled them down to
 * what currently exists.  In the future, the MDContext class might go away and backreferences
 * could be part of the class for which the context has been created--but we started with this
 * current model while we were trying to understand when there was a context change and what
 * required the change; in fact, there are still questions that arise in my mind, yet I have not
 * yet created tests that might tease the answer out.  I do know, however, that one or more tests
 * in the MDMangTestStandard class had helped define what we have--I no longer have record of
 * which tests were solely responsible for revealing some of the special context/backreference
 * cases (e.g., could have been that a backreference to an internal template argument got used
 * in a certain way).
 */
public class MDContext {
	private List<String> backrefNames = new ArrayList<>();
	private List<MDDataType> backrefParametersMDDataType = new ArrayList<>();
	// TODO: checking this out 20140514: possible that reg params and template params just two
	// lists that and no stacking of lists is needed.
	private List<MDDataType> backrefTemplateParametersMDDataType = new ArrayList<>();

	public enum MDContextType {
		MODIFIER, FUNCTION, TEMPLATE
	}

	public MDContext(MDContext copyFrom, MDContextType context) {
		switch (context) {
			// 20170418 info: eliminated use by MDModifierType and MDSpecialName (not needed
			//  for these), but MODIFIER is needed in MDTemplateParameter ($1 in its parsing)
			//  where it creates an underlying MDObjectCPP.  So it really just needs a regular
			//  context push.
			// TODO: Probably should pull the context push from within the MDMang (for an
			//  MDObject) to just within the MDObjectCPP (I don't think it is necessarily needed
			//  for others though they "might" need to store off an MDFragment (but only if we
			//  are doing MDReusable???).
			case MODIFIER:
				backrefNames = copyFrom.backrefNames;
				backrefParametersMDDataType = copyFrom.backrefParametersMDDataType;
				backrefTemplateParametersMDDataType = copyFrom.backrefTemplateParametersMDDataType;
				break;
			case FUNCTION:
				backrefNames = copyFrom.backrefNames;
				backrefParametersMDDataType = copyFrom.backrefParametersMDDataType;
				backrefTemplateParametersMDDataType = copyFrom.backrefTemplateParametersMDDataType;
				break;
			case TEMPLATE:
				backrefNames = new ArrayList<>();
				backrefParametersMDDataType = new ArrayList<>();
				backrefTemplateParametersMDDataType = copyFrom.backrefTemplateParametersMDDataType;
				break;
		}
	}

	public MDContext() {
	}

	public void addBackrefName(String name) {
		backrefNames.add(name);
	}

	public String getBackrefName(int index) throws MDException {
		if (index >= backrefNames.size() || index < 0) {
			throw new MDException("Backref Names stack violation");
		}
		return backrefNames.get(index);
	}

	public void addBackrefFunctionParameterMDDataType(MDDataType dt) {
		backrefParametersMDDataType.add(dt);
	}

	public void addBackrefTemplateParameterMDDataType(MDDataType dt) {
		backrefTemplateParametersMDDataType.add(dt);
	}

	public MDDataType getBackrefFunctionParameterMDDataType(int index) throws MDException {
		if (index >= backrefParametersMDDataType.size() || index < 0) {
			throw new MDException("Parameter stack violation");
		}
		return backrefParametersMDDataType.get(index);
	}

	public MDDataType getBackrefTemplateParameterMDDataType(int index) throws MDException {
		if (index >= backrefTemplateParametersMDDataType.size() || index < 0) {
			throw new MDException("Template parameter stack violation");
		}
		return backrefTemplateParametersMDDataType.get(index);
	}
}

/******************************************************************************/
/******************************************************************************/
