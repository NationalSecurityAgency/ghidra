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
package ghidra.xtext.sleigh.ui

import ghidra.xtext.sleigh.sleigh.DefineSym
import ghidra.xtext.sleigh.sleigh.SUBTABLESYM
import ghidra.xtext.sleigh.sleigh.aliasSym
import ghidra.xtext.sleigh.sleigh.integerValue
import ghidra.xtext.sleigh.sleigh.macroDefine
import ghidra.xtext.sleigh.sleigh.printpiece
import ghidra.xtext.sleigh.sleigh.subconstructor
import java.math.BigInteger
import org.eclipse.emf.common.util.EList
import org.eclipse.emf.ecore.EObject
import org.eclipse.xtext.conversion.ValueConverterException
import org.eclipse.xtext.nodemodel.util.NodeModelUtils
import org.eclipse.xtext.ui.editor.hover.html.DefaultEObjectHoverProvider
import org.eclipse.xtext.util.Strings

class SleighEObjectHoverProvider extends DefaultEObjectHoverProvider {

	EObject model
	
	override boolean hasHover(EObject o) {
		if (o instanceof integerValue) { return true; }
		return super.hasHover(o)
	}

	override String getFirstLine(EObject o) {
		var label = getLabel(o);
		var str = o.eClass().getName();
		if (label == null) {
			str += "";
		} else {
			str = " <b>" + label + "</b>";
		}
		return str;
	}

	override String getLabel(EObject element) {
		switch element {
			DefineSym:
				return " <b>" + element.name + "</b>"
			default:
				return super.getLabel(element)
		}
	}

	override String getDocumentation(EObject element) {
		switch element {
			DefineSym:
				return getDefineSymText(element)
			SUBTABLESYM:
				return getSubTableText(element)
			aliasSym:
			    return getSubTableText(element)
			integerValue:
				return getIntegerFormats(element)
			default:
				return super.getDocumentation(element)
		}
	}
	
	def getIntegerFormats(integerValue value) {
		var retStr = "";
		var valueOf = getIntValue(value)
		
		retStr = retStr + "<p style=\"color:red;line-height:50%;\">" + "0b" + valueOf.toString(2) + "</p>\n"
		retStr = retStr + "<p style=\"color:red;line-height:50%;\">" + "0x" + valueOf.toString(16) + "</p>\n"
		retStr = retStr + "<p style=\"color:red;line-height:50%;\">" + "  " + valueOf.toString(10) + "</p>\n"
		
		if (retStr.length == 0) {
			return value.value;
		}
		return retStr;
	}
	
	def getIntValue(integerValue value) {
		var parseString = value.value;
		var string = value.value
		if (Strings.isEmpty(parseString))
			throw new NumberFormatException("Couldn't convert empty string to an int value.");
		try {
			var radix = 10;
			if (parseString.startsWith("0x") || parseString.startsWith("0X")) {
				parseString = string.substring(2);
				radix=16;
			}
			if (parseString.startsWith("0b") || parseString.startsWith("0B")) {
				parseString = string.substring(2);
				radix=2;
			}
			return new BigInteger(parseString,radix);
		} catch (NumberFormatException e) {
			throw new NumberFormatException("Couldn't convert '" + string + "' to a BigInteger value.");
		}
	}

	def getDefineSymText(DefineSym element) {
		var retStr = "";
		model = element.eResource.contents.get(0);
		var macDefs = model.eAllContents.filter(typeof(macroDefine));
		var len = "";
		while (macDefs.hasNext) {
			var next = macDefs.next;
			if (next.defineType.equals("@define")) {
				if (next.definename.name == element.name) {
					retStr = retStr + "<p style=\"color:red;line-height:100%;\">" + next.value + "</p>\n"
				}
			}
		}
		if (retStr.length == 0) {
			return element.name;
		}
		return retStr;
	}

	def getSubTableText(SUBTABLESYM element) {
		var retStr = "";
		model = element.eResource.contents.get(0);
		var subs = model.eAllContents.filter(typeof(subconstructor));
		var len = "";
		while (subs.hasNext) {
			var next = subs.next;
			if (next.tableName.name == element.name) {
				retStr = retStr + "<p style=\"color:red;line-height:100%;\">" + formatString(next.print.printpieces) +
					" is " + formatConstraintString(next.match.constraints) + "</p>\n"
			}
		}
		if (retStr.length == 0) {
			return element.name;
		}
		return retStr;
	}
	
	def getSubTableText(aliasSym element) {
		var retStr = "";
		model = element.eResource.contents.get(0);
		var subs = model.eAllContents.filter(typeof(subconstructor));
		while (subs.hasNext) {
			var next = subs.next;
			if (next.tableName.name == element.sym) {
				retStr = retStr + "<p style=\"color:red;line-height:100%;\">" + formatString(next.print.printpieces) +
					" is " + formatConstraintString(next.match.constraints) + "</p>\n"
			}
		}
		if (retStr.length != 0) {
			return retStr;
		}
		var macDefs = model.eAllContents.filter(typeof(macroDefine));
		while (macDefs.hasNext) {
			var next = macDefs.next;
			if (next.defineType.equals("@define")) {
				if (next.definename.name == element.sym) {
					retStr = retStr + "<p style=\"color:red;line-height:100%;\">" + next.value + "</p>\n"
				}
			}
		}
		if (retStr.length == 0) {
			return element.sym;
		}
		return retStr;
	}

	def String formatString(EList<printpiece> list) {
		var str = "<span style=\"color:#0000FF;\">";
		var iter = list.iterator;
		while (iter.hasNext) {
			var piece = iter.next;
			if (piece.str == null) {
				if (piece.sym != null) {
					str += piece.sym.sym;
				} else {
					str = '{empty}'
				}
			} else {
				str += piece.str;
			}
		}
		str += "</span>"
		str
	}

	def String formatConstraintString(EObject o) {
		var node = NodeModelUtils.getNode(o);
		return node.text
	}

}