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

import java.util.*;

import mdemangler.*;
import mdemangler.datatype.*;
import mdemangler.datatype.complex.MDComplexType;
import mdemangler.datatype.extended.MDExtendedType;
import mdemangler.datatype.modifier.MDModifierType;

/**
 * This class represents the template arguments list portion of a
 * Microsoft mangled symbol.
 */
public class MDTemplateArgumentsList extends MDParsableItem {
	private List<MDDataType> args = new ArrayList<>();
	private List<Boolean> commaDelimiter = new ArrayList<>(); // For two MSFT bugs

	public MDTemplateArgumentsList(MDMang dmang) {
		super(dmang);
	}

	public int getNumArgs() {
		return args.size();
	}

	public MDDataType getArg(int index) {
		return args.get(index);
	}

	@Override
	protected void parseInternal() throws MDException {
		boolean argsDone = false;
		boolean needsComma = false; // For "delimiters" MSFT bug
		while (!argsDone) {
			char code = dmang.peek();
			MDDataType dt;
			switch (code) {
				case '@':
					dmang.increment();
					argsDone = true;
					break;
				case MDMang.DONE:
					argsDone = true;
					break;
				case 'X':
					dmang.increment();
					dt = new MDVoidDataType(dmang);
					dt.parse();
					commaDelimiter.add(needsComma);
					needsComma = true;
					args.add(dt);
					// Unlike an argument of a function, when "void" is first argument of a
					//  template, it does not terminate the arguments list.
					// Do not put into backreference parameter list.
					break;
				case 'Z':
					throw new MDException("Varargs not allowed as template parameter");
				case '?': {
					dmang.increment();
					// TODO: make this the new MDTemplateParameter
					MDEncodedNumber x = new MDEncodedNumber(dmang);
					x.parse();
					MDDataType datatype = new MDDataType(dmang);
					datatype.setTypeName("`template-parameter-" + x + "'");
					dt = datatype;
					commaDelimiter.add(needsComma);
					needsComma = true;
					args.add(dt);
					dmang.addBackrefTemplateParameterMDDataType(dt);
				}
					break;
				case '$':
					// "$$$V" and "$$V" (latter is MSVC15 version):  case of ignore as argument.
					if ((dmang.peek(1) == '$') && (dmang.peek(2) == '$') &&
						(dmang.peek(3) == 'V')) {
						dmang.increment();
						dmang.increment();
						dmang.increment();
						dmang.increment();
						if (args.isEmpty()) {
							// MDMANG SPECIALIZATION USED.
							// For "delimiters" MSFT bug: setting true even though we are
							//  skipping parameter.
							needsComma = dmang.emptyFirstArgComma(this);
						}
						continue;
					}
					if ((dmang.peek(1) == '$') && (dmang.peek(2) == 'V')) {
						dmang.increment();
						dmang.increment();
						dmang.increment();
						if (args.isEmpty()) {
							// MDMANG SPECIALIZATION USED.
							// For "delimiters" MSFT bug: setting true even though we are
							//  skipping parameter.
							needsComma = dmang.emptyFirstArgComma(this);
						}
						continue;
					}
					if (dmang.peek(1) == '$') { // This is the same as the "default" case below
						dt = MDDataTypeParser.parsePrimaryDataType(dmang, true);
						dt.parse();
						commaDelimiter.add(needsComma);
						needsComma = true;
						args.add(dt);
						// Only MDModifierType hits here (because $$ will only be that type
						// (decision AT THE MOMENT is that they extend MDModifierType)"
						// We are keeping the others here for now as this $$ case is the same
						// as the "default" case below.
						if ((dt instanceof MDModifierType) || (dt instanceof MDExtendedType) ||
							(dt instanceof MDComplexType)) {
							dmang.addBackrefTemplateParameterMDDataType(dt);
						}
					}
					else {
						MDTemplateConstant tp = new MDTemplateConstant(dmang);
						tp.parse();
						StringBuilder tmpBuilder = new StringBuilder();
						tp.insert(tmpBuilder);
						String tpName = tmpBuilder.toString();
						if (!tpName.isEmpty()) {
							// MSFT does not put it on the arguments list or create a
							// backreference for it, BUT... MSFT will note that it needs a
							// comma in the arguments list, which is WRONG.
							MDDataType datatype = new MDDataType(dmang);
							datatype.setTypeName(tpName);
							dt = datatype;
							commaDelimiter.add(needsComma);
							needsComma = true;
							args.add(dt);
							dmang.addBackrefTemplateParameterMDDataType(dt);
						}
						else if (args.isEmpty()) { // See note above.
							// To overcome MSFT comma bug
							// See//TODO: for MSFT output (when we do it), need to note the need
							//  need for a comma before our "real" first parameter.
							// MDMANG SPECIALIZATION USED.
							// For "delimiters" MSFT bug: setting true even though we are
							// skipping parameter.
							needsComma = dmang.emptyFirstArgComma(this);
						}
					}
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
					dt = dmang.getBackreferenceTemplateParameterMDDataType(index);
					// MDMANG SPECIALIZATION USED.
					commaDelimiter.add(dmang.templateBackrefComma(this));
					// For "delimiters" MSFT bug: setting false here for backreference.
					needsComma = true;
					args.add(dt);
					break;
				default:
					dt = MDDataTypeParser.parsePrimaryDataType(dmang, true);
					dt.parse();
					commaDelimiter.add(needsComma);
					needsComma = true;
					args.add(dt);
					if ((dt instanceof MDModifierType) || (dt instanceof MDExtendedType) ||
						(dt instanceof MDComplexType)) {
						dmang.addBackrefTemplateParameterMDDataType(dt);
					}
					break;
			}
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (args.size() > 0) {
			// boolean firstArgDone = false;
			Iterator<Boolean> delimIter = commaDelimiter.iterator();
			for (MDType arg : args) {
				if (delimIter.next()) {
					dmang.appendString(builder, ",");
				}
				// firstArgDone = true;
				StringBuilder argBuilder = new StringBuilder();
				arg.insert(argBuilder);
				dmang.appendString(builder, argBuilder.toString());
			}
		}
	}
}

/******************************************************************************/
/******************************************************************************/
