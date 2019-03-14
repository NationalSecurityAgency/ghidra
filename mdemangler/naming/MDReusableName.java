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

	public MDReusableName(MDMang dmang) {
		super(dmang);
	}

	public String getName() {
		if (fragment != null) {
			return fragment.getName();
		}
		if (templateName != null) {
			return templateName.getName();
		}
		return "";
	}

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
		if (fragment != null) {
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
				fragment.parse();
				dmang.addBackrefName(fragment.getName());
				break;
		}
	}
}

/******************************************************************************/
/******************************************************************************/
