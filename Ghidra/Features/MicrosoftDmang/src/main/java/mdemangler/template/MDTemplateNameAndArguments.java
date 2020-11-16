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
package mdemangler.template;

import mdemangler.*;
import mdemangler.naming.MDBasicName;

/**
 * This class represents the template name and arguments list portion of a
 * Microsoft mangled symbol.
 */
public class MDTemplateNameAndArguments extends MDParsableItem {
	private MDBasicName templateName;
	private MDTemplateArgumentsList args;

	public MDTemplateNameAndArguments(MDMang dmang) {
		super(dmang);
	}

	public boolean isConstructor() {
		return templateName.isConstructor();
	}

	public boolean isDestructor() {
		return templateName.isDestructor();
	}

	public boolean isTypeCast() {
		return templateName.isTypeCast();
	}

	public void setName(String name) {
		templateName.setName(name);
	}

	public String getName() {
		return templateName.getName();
	}

	public void setCastTypeString(String castTypeString) {
		if (templateName == null) {
			return;
		}
		templateName.setCastTypeString(castTypeString);
	}

	public MDTemplateArgumentsList getArgumentsList() {
		return args;
	}

	@Override
	public void insert(StringBuilder builder) {
		StringBuilder argsBuilder = new StringBuilder();
		args.insert(argsBuilder);
		dmang.insertString(builder, ">");
		if ((argsBuilder.length() != 0) && (argsBuilder.charAt(argsBuilder.length() - 1) == '>')) {
			dmang.insertString(builder, " ");
		}
		dmang.insertString(builder, argsBuilder.toString());
		dmang.insertString(builder, "<");
		templateName.insert(builder);
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() != '?' && dmang.peek(1) != '$') {
			throw new MDException("Invalid TemplateNameandArguments");
		}
		dmang.increment(); // skip the '?'
		dmang.increment(); // skip the '$'
		dmang.pushTemplateContext();
		templateName = new MDBasicName(dmang);
		templateName.parse();
		args = new MDTemplateArgumentsList(dmang);
		args.parse();
		dmang.popContext();
	}
}

/******************************************************************************/
/******************************************************************************/
