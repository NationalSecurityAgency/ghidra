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
package mdemangler.naming;

import ghidra.util.Msg;
import mdemangler.*;
import mdemangler.object.MDObjectCPP;
import mdemangler.template.MDTemplateNameAndArguments;

/**
 * This class represents the "Basic" part of a qualified name (following wiki page
 *  naming convention for Microsoft Demangler).
 */
public class MDBasicName extends MDParsableItem {
	MDSpecialName specialName;
	MDTemplateNameAndArguments templateNameAndArguments;
	MDReusableName reusableName;
	MDObjectCPP embeddedObject;
	MDQualification embeddedObjectQualification;
	String nameModifier;

	public MDBasicName(MDMang dmang) {
		super(dmang);
	}

	public void setNameModifier(String nameModifier) {
		this.nameModifier = nameModifier;
	}

	public boolean isConstructor() {
		if (specialName != null) {
			return specialName.isConstructor();
		}
		if (templateNameAndArguments != null) {
			return templateNameAndArguments.isConstructor();
		}
		return false;
	}

	public boolean isDestructor() {
		if (specialName != null) {
			return specialName.isDestructor();
		}
		if (templateNameAndArguments != null) {
			return templateNameAndArguments.isDestructor();
		}
		return false;
	}

	public boolean isTypeCast() {
		if (specialName != null) {
			return specialName.isTypeCast();
		}
		if (templateNameAndArguments != null) {
			return templateNameAndArguments.isTypeCast();
		}
		return false;
	}

	/**
	 * Returns the RTTI number:{0-4, or -1 if not an RTTI}
	 * @return int RTTI number:{0-4, or -1 if not an RTTI}
	 */
	public int getRTTINumber() {
		if (specialName != null) {
			return specialName.getRTTINumber();
		}
		return -1;
	}

	public boolean isString() {
		if (specialName != null) {
			return specialName.isString();
		}
		return false;
	}

	public MDString getMDString() {
		if ((specialName != null) && specialName.isString()) {
			return specialName.getMDString();
		}
		return null;
	}

	public String getName() {
		if (specialName != null) {
			return specialName.getName();
		}
		if (templateNameAndArguments != null) {
			return templateNameAndArguments.getName();
		}
		if (reusableName != null) {
			return reusableName.getName();
		}
		return "";
	}

	/**
	 * Return the embedded object (essentially what could stand on its own as a mangled
	 *  symbol) that is used as part of the name of mangled object 
	 * @return The embedded object that essentially represents this MDBasicName.
	 */
	public MDObjectCPP getEmbeddedObject() {
		return embeddedObject;
	}

	public void setName(String name) {
		// We should only get a call for setName() due to a contructor or destructor,
		// which come from MDSpecialName or from MDTemplateNameAndArguments.
		if (specialName != null) {
			specialName.setName(name);
		}
		else if (templateNameAndArguments != null) {
			templateNameAndArguments.setName(name);
		}
		else {
			Msg.warn(this, "name cannot be set");
		}
	}

	// This needs to be separate from nameModifier.  The contrived example that follows
	//  shows that both a nameModifier as well as a castTypeString should be considered
	//  separately, as both can exist.  Trying to manage multiple calls to
	//  setNameModifier() would not work because their order would need to be managed and
	//  the results merged.  Makes no sense to have anything but two separate notions.
	//	"??Bname@@O7AAHXZ"
	//	"[thunk]:protected: virtual __cdecl name::operator int`adjustor{8}' (void)"
	public void setCastTypeString(String castTypeString) {
		if (specialName != null) {
			specialName.setCastTypeString(castTypeString);
		}
		else if (templateNameAndArguments != null) {
			templateNameAndArguments.setCastTypeString(castTypeString);
		}
		else {
			Msg.warn(this, "castTypeString cannot be set");
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (reusableName != null) {
			reusableName.insert(builder);
		}
		else if (specialName != null) {
			specialName.insert(builder);
		}
		else if (embeddedObject != null) {
			embeddedObject.insert(builder);
		}
		else {
			templateNameAndArguments.insert(builder);
		}
		if (nameModifier != null) {
			builder.append(nameModifier);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		// First pass can only have name fragment of special name
		if (dmang.peek() == '?') {
			if (dmang.peek(1) == '$') {
				templateNameAndArguments = new MDTemplateNameAndArguments(dmang);
				templateNameAndArguments.parse();
			}
			else if (dmang.peek(1) == '?') {
				// Seems to only hit here for second '?' of "???" sequence.
				embeddedObject = new MDObjectCPP(dmang);
				embeddedObject.parse();
				embeddedObjectQualification = new MDQualification(dmang);
				embeddedObjectQualification.parse(); //Value not used, but must be parsed.
			}
			else {
				dmang.increment();
				specialName = new MDSpecialName(dmang, 1);
				specialName.parse();
			}
		}
		else {
			reusableName = new MDReusableName(dmang);
			reusableName.parse();
		}
	}
}

/******************************************************************************/
/******************************************************************************/
