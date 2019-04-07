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
import mdemangler.naming.MDFragmentName;
import mdemangler.object.MDObject;
import mdemangler.object.MDObjectCPP;

/**
 * This class represents a the template constant portion of a
 * Microsoft mangled symbol.  Usually found as an argument to a template.
 */
public class MDTemplateConstant extends MDParsableItem {
	private String name;
	private String addressMaybe; // Currently not emitted.

	public MDTemplateConstant(MDMang dmang) {
		super(dmang);
	}

	public String getAddressMaybe() {
		return addressMaybe;
	}

	@Override
	protected void parseInternal() throws MDException {
		char code = dmang.getAndIncrement();
		addressMaybe = "";
		name = "";
		// We do not yet know what these numbers are, so giving them meaningless names for now.
		MDSignedEncodedNumber a, b, c, nameNum;
		switch (code) {
			case '$': {
				code = dmang.getAndIncrement();
				switch (code) {
					case '0':
						nameNum = new MDSignedEncodedNumber(dmang);
						nameNum.parse();
						name = nameNum.toString();
						break;
					case '1': { // Seen as "$1?name@@data@@modifier"
						// TODO: Not sure if this push and pop belong here or with the $$F flag
						//  for the particular data symbol under test
						dmang.pushModifierContext();
						MDObject object = new MDObjectCPP(dmang);
						object.parse();
						dmang.popContext();
						StringBuilder builder = new StringBuilder();
						object.insert(builder);
						dmang.insertString(builder, "&");
						name = builder.toString();
						// name = "&" + object;
					}
						break;
					case '2': // TODO: Currently, we have no test data for this.
						a = new MDSignedEncodedNumber(dmang);
						a.parse();
						String aStr = a.toString();
						// 20140630: seems that '\'' is not there in $2a'b (documentation
						// notation failure--the single quote (any type) is not really in the
						// mangled string)
						b = new MDSignedEncodedNumber(dmang);
						b.parse();
						if (aStr.charAt(0) == '-') {
							name = "-";
							aStr = aStr.substring(1, aStr.length());
						}
						name += aStr.charAt(0) + ".";
						if (aStr.length() > 1) {
							name += aStr.substring(1, aStr.length());
						}
						name += "e" + b;
						break;
					case 'D':
						a = new MDSignedEncodedNumber(dmang);
						a.parse();
						name = "`template-parameter" + a + "'";
						break;
					case 'E': {
						// Do not do a pushModifierContext here.
						MDObject object = new MDObjectCPP(dmang);
						object.parse();
						StringBuilder builder = new StringBuilder();
						object.insert(builder);
						name = builder.toString();
					}
						break;
					case 'F':
						// 20140630: seems that '\'' is not there in $Fa'b (documentation
						// notation failure--the single quote (any type) is not really in the
						// mangled string)						
						a = new MDSignedEncodedNumber(dmang);
						a.parse();
						b = new MDSignedEncodedNumber(dmang);
						b.parse();
						name = "{" + a + "," + b + "}";
						break;
					case 'G':
						// 20140630: seems that '\'' is not there in $Ga'b'c (documentation
						// notation failure--the single quote (any type) is not really in the
						// mangled string)						
						a = new MDSignedEncodedNumber(dmang);
						a.parse();
						b = new MDSignedEncodedNumber(dmang);
						b.parse();
						c = new MDSignedEncodedNumber(dmang);
						c.parse();
						name = "{" + a + "," + b + "," + c + "}";
						break;
					case 'H': {
						// Do not do a pushModifierContext here.
						MDObject object = new MDObjectCPP(dmang);
						object.parse();
						StringBuilder builder = new StringBuilder();
						object.insert(builder);
						a = new MDSignedEncodedNumber(dmang); // Signed is valid here (20140630)
						a.parse();
						dmang.insertString(builder, "{");
						dmang.appendString(builder, ",");
						dmang.appendString(builder, a.toString());
						dmang.appendString(builder, "}");
						name = builder.toString();
						// name = "{" + object + "," + a + "}";
					}
						break;
					case 'I': { // Used in some cases ($$issue!!!!!!)
						// 20140630: seems that '\'' is not there in $Ix'y (documentation
						// notation failure--the single quote (any type) is not really in the
						// mangled string)						
						// It also seems that the second parameter CAN be negative: $Ixa, where
						// x is some object, and a is some signed number
						// Do not do a pushModifierContext here.
						MDObject object = new MDObjectCPP(dmang);
						object.parse();
						StringBuilder builder = new StringBuilder();
						object.insert(builder);
						a = new MDSignedEncodedNumber(dmang); // Signed is valid here (20140630)
						a.parse();
						b = new MDSignedEncodedNumber(dmang); // Signed is valid here (20140630)
						b.parse();
						dmang.insertString(builder, "{");
						dmang.appendString(builder, ",");
						dmang.appendString(builder, a.toString());
						dmang.appendString(builder, ",");
						dmang.appendString(builder, b.toString());
						dmang.appendString(builder, "}");
						name = builder.toString();
						// name = "{" + object + "," + a + "," + b + "}";
					}
						break;
					case 'J': { // Used in some cases ($$issue!!!!!!)
						// 20140630: seems that '\'' is not there in $Jx'y'z (documentation
						// notation failure--the single quote (any type) is not really in the
						// mangled string)						
						// It also seems that the second, third, and fourth parameters CAN be
						// negative: $Jxabc, where x is some object, and a, b, and care some
						// signed numbers
						// Do not do a pushModifierContext here.
						MDObject object = new MDObjectCPP(dmang);
						object.parse();
						StringBuilder builder = new StringBuilder();
						object.insert(builder);
						a = new MDSignedEncodedNumber(dmang); // Signed is valid here (20140630)
						a.parse();
						b = new MDSignedEncodedNumber(dmang); // Signed is valid here (20140630)
						b.parse();
						c = new MDSignedEncodedNumber(dmang); // Signed is valid here (20140630)
						c.parse();
						dmang.insertString(builder, "{");
						dmang.appendString(builder, ",");
						dmang.appendString(builder, a.toString());
						dmang.appendString(builder, ",");
						dmang.appendString(builder, b.toString());
						dmang.appendString(builder, ",");
						dmang.appendString(builder, c.toString());
						dmang.appendString(builder, "}");
						name = builder.toString();
						// name = "{" + object + "," + a + "," + b + "," + c + "}";
					}
						break;
					case 'Q':
						a = new MDSignedEncodedNumber(dmang);
						a.parse();
						name = "`non-type-template-parameter" + a + "'";
						break;
					case 'R': {
						MDFragmentName fragment = new MDFragmentName(dmang);
						fragment.parse();
						MDSignedEncodedNumber addressMaybeNum = new MDSignedEncodedNumber(dmang);
						addressMaybeNum.parse();
						addressMaybe = addressMaybeNum.toString();
						StringBuilder builder = new StringBuilder();
						fragment.insert(builder);
						name = builder.toString();
					}
						break;
					case 'S': // Empty parameter (generally an empty list?)
						name = "";
						break;
					default:
						throw new MDException("Unknown Template Constant: $" + code + " code");
				}
			}
				break;
			default:
				throw new MDException("Template Parameter needs work: " + code + " code");
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertString(builder, name);
	}
}

/******************************************************************************/
/******************************************************************************/
