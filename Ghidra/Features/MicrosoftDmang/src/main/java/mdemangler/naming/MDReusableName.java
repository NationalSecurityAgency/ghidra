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

import mdemangler.*;
import mdemangler.template.MDTemplateNameAndArguments;

/**
 * This class represents a reusable name (whether a fragment, template name, or
 * backreference index of a previous reusable name)--where one is allowed--within
 * a Microsoft mangled symbol.
 */
public class MDReusableName extends MDParsableItem {
	MDFragmentName fragment;
	MDTemplateNameAndArguments templateName;
	String specialName;

	public MDReusableName(MDMang dmang) {
		super(dmang);
	}

	public String getName() {
		if (specialName != null) {
			return specialName;
		}
		if (fragment != null) {
			return fragment.getName();
		}
		if (templateName != null) {
			return templateName.getName();
		}
		return "";
	}

	// This method is currently not called... But if it is, then we might need to consider
	//  crafting the specialName on-the-fly, but would also want a flag that signifies it was
	//  at dmang offset 1 in the mangled string so we would have to know whether to use
	//  the crafted special name or the regular name.
	public void setName(String name) {
		if (fragment != null) {
			fragment.setName(name);
		}
		// DO NOT DELETE THE FOLLOWING FRAGMENT--part of future work
//		else if (qualifiedName != null) { //TODO: do we need this 20140520
//			qualifiedName.setName(name);
//		}
		else if (templateName != null) {
			templateName.setName(name);
		}
		return;
	}

	@Override
	public void insert(StringBuilder builder) {
		if (specialName != null) {
			dmang.insertString(builder, specialName);
		}
		else if (fragment != null) {
			fragment.insert(builder);
		}
		else {
			templateName.insert(builder);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		// First pass can only have name fragment of special name
		char code = dmang.peek();
		switch (code) {
//			case '$': //might not be used.
//				dmang.getAndIncrement();
//				break;
			case '?':
				templateName = new MDTemplateNameAndArguments(dmang);
				templateName.parse();
				dmang.addBackrefName(templateName.toString());
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				dmang.increment();
				int index = code - '0';
				fragment = new MDFragmentName(dmang);
				fragment.setName(dmang.getBackreferenceName(index));
				break;
			default:
				fragment = new MDFragmentName(dmang);
				int loc = dmang.getIndex();
				fragment.parse();
				if (loc == 1) {
					processSpecialName(fragment.getName());
				}
				dmang.addBackrefName(fragment.getName()); // note that back-ref gets standard name
				break;
		}
	}

	// MOVED/ADAPTED FROM MDSpecialName class (where will this eventually land?)
	//
	// Neither MSFT nor LLVM output these special names.
	// Breaks the "norm" of MSFT model we have been following.
	// The output format is our creation (trying to follow MSFT convention with ticks and braces).
	// The "?$" prefix on these are templates in MSFT's reserved space and could collide
	// with a template symbol under the MSFT scheme.
	//
	// Following the model of MSFT Guard output strings even though the mangled form does not
	//  follow MSFT's scheme.  Change is that we are not outputting the extraneous tick as is seen
	//  in the middle of `local static guard'{2}', but we are still increasing the string value
	//  that is in braces by one from the coded value.  Thus, we are outputting
	//  `thread safe static guard{1}' for "?$TSS0@".  We can reconsider this later.
	public void processSpecialName(String inputName) throws MDException {
		if (inputName.startsWith("$TSS")) {
			//dmang.parseInfoPush(0, "thread safe static guard");
			String guardNumberString = inputName.substring("$TSS".length());
			validateNumberString(guardNumberString);
			//dmang.parseInfoPop();
			specialName = "`thread safe static guard{" + guardNumberString + "}'";
		}
		else if (inputName.equals("$S1")) {
			// The '1' in "?$S1" is currently hard-coded in the LLVM code, but I believe we
			// should still enclose it in braces... subject to change.
			//dmang.parseInfoPush(0, "nonvisible static guard");
			specialName = "`nonvisible static guard{1}'";
			//dmang.parseInfoPop();
		}
		else if (inputName.startsWith("$RT")) {
			//dmang.parseInfoPush(0, "reference temporary");
			String manglingNumberString = inputName.substring("$RT".length());
			validateNumberString(manglingNumberString);
			//dmang.parseInfoPop();
			specialName = "`reference temporary{" + manglingNumberString + "}'";
		}
	}

	/**
	 * Validates Number (it is output as Number << '@' where Number is an unsigned int, so we are
	 *  capturing it as a string of digits.
	 *  Built for what seems to be LLVM-specific mangling.  Does not follow MSFT model.
	 * @throws MDException Upon invalid character sequence or out of characters.
	 */
	private void validateNumberString(String numberString) throws MDException {
		numberString.getBytes();
		for (int c : numberString.getBytes()) {
			if (!Character.isDigit(c)) { // includes end of string (MDMang.DONE)
				throw new MDException("Illegal character in Number: " + c);
			}
		}
	}

}

/******************************************************************************/
/******************************************************************************/
