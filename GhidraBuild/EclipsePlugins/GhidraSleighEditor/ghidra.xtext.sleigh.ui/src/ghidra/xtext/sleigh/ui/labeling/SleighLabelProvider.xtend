/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an &quot;AS IS&quot; BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.xtext.sleigh.ui.labeling

import com.google.inject.Inject
import java.util.Iterator
import org.eclipse.emf.common.util.EList
import org.eclipse.emf.ecore.EObject
import org.eclipse.emf.edit.ui.provider.AdapterFactoryLabelProvider
import org.eclipse.jface.viewers.StyledString
import org.eclipse.xtext.naming.IQualifiedNameProvider
import org.eclipse.xtext.naming.QualifiedName
import org.eclipse.xtext.ui.label.DefaultEObjectLabelProvider
import ghidra.xtext.sleigh.sleigh.DefineSym
import ghidra.xtext.sleigh.sleigh.SUBTABLESYM
import ghidra.xtext.sleigh.sleigh.VARSYM
import ghidra.xtext.sleigh.sleigh.baseconstructor
import ghidra.xtext.sleigh.sleigh.constraint
import ghidra.xtext.sleigh.sleigh.constructprint
import ghidra.xtext.sleigh.sleigh.contextfielddef
import ghidra.xtext.sleigh.sleigh.fielddef
import ghidra.xtext.sleigh.sleigh.integerValue
import ghidra.xtext.sleigh.sleigh.macroDefine
import ghidra.xtext.sleigh.sleigh.printpiece
import ghidra.xtext.sleigh.sleigh.subconstructor
import ghidra.xtext.sleigh.sleigh.varattach
import ghidra.xtext.sleigh.sleigh.varnodedef

import static extension org.eclipse.emf.ecore.util.EcoreUtil.*
import static extension org.eclipse.xtext.EcoreUtil2.*

/**
 * Provides labels for EObjects.
 * 
 * See https://www.eclipse.org/Xtext/documentation/304_ide_concepts.html#label-provider
 */
class SleighLabelProvider extends DefaultEObjectLabelProvider {
	@Inject
	new(AdapterFactoryLabelProvider delegate) {
		super(delegate);
	}

	@Inject
	private IQualifiedNameProvider nameProvider;

	QualifiedName qn

	EObject model

	Iterator<varattach> varatt

	def String text(EObject eObject) {
		qn = nameProvider.getFullyQualifiedName(eObject);
		if(qn == null) {
			return getObjectText(eObject);
		}

		return qn.toString();
	}
	
	def String getObjectText(EObject element) {
		switch element {
			macroDefine:
				element.defineType // + element.definename.name + " = " + element.value
			VARSYM:
				element.name + " : " + getSizeStr((element.eContainer.eContainer as varnodedef).size)
			SUBTABLESYM:
				element.name
			contextfielddef:
				element.name
			fielddef:
				element.name
			subconstructor:
				doGetText(element.tableName) + ':'
			baseconstructor:
				':' + doGetText(element.print)
			constructprint:
				formatString(element.printpieces)
			constraint:
				element.eClass.baseName
			default: {
				//System.out.println(element.class.simpleName)
				element.class.simpleName
				}
		}
	}

	String possible;

	def getfielddefText(fielddef element) {
		// find all var attaches and display possible names
		var len = getVarAttachesForElement(element)
		return convertToStyledString('field ' + element.name).append(
			"  " + len + " " + '  (' + element.start.value + ',' + element.end.value + ')' +
				(if(element.isSigned()) ' signed' else ''), StyledString::QUALIFIER_STYLER).append("\n\n" + possible);
	}
	
	def getcontextfielddefText(contextfielddef element) {
		// find all var attaches and display possible names
		var len = getVarAttachesForElement(element)
		// is in a context, put out the name
		return convertToStyledString('context ' + element.name).append(
			"  " + len + " " + '  (' + element.start.value + ',' + element.end.value + ')' +
				(if(element.isSigned()) ' signed' else ''), StyledString::QUALIFIER_STYLER).append("\n\n" + possible);
	}
	
	protected def String getVarAttachesForElement(EObject element) {
		model = element.eResource.contents.get(0);
		varatt = model.eAllContents.filter(typeof(varattach));
		possible = "";
		var len = "";
		while (varatt.hasNext) {
			var next = varatt.next;
			var vlist = next.valuelist.valuelist.listIterator;
			while (vlist.hasNext) {
				var v = vlist.next;
				if (v.sym.equals(element)) {
					var viter = next.vlist.varDefList.iterator;
					possible = "attached to: "
					while (viter.hasNext) {
						var varname = viter.next;
						var vref = varname.varpart;
						if (vref != null) {
							var vdef = vref.getContainerOfType(typeof(varnodedef));
							if (vdef != null) {
								var size = vdef.size.value;
								len = size; // works even if is a $Define
							}
							possible = possible + vref.name + " ";
						}
					}
				}
			}
		}
		len
	}
		
	def getDefineSymText(DefineSym element) {
		// find all var attaches and display possible names
		var retStr = "";
		model = element.eResource.contents.get(0);
		var macDefs = model.eAllContents.filter(typeof(macroDefine));
		possible = "";
		var len = "";
		while (macDefs.hasNext) {
			var next = macDefs.next;
			if (next.defineType.equals("@define")) {
				if (next.definename.name == element.name) {
					retStr = retStr + next.value + "\r\n"
				}
			}
		}
		if (retStr.length == 0) {
			return super.doGetText(element);
		}
		return retStr;
	}	

	override protected doGetText(Object element) {
		if(element == null) return null;
		// System.out.println("Label:" + element.class.baseName + " : " + element);
		switch element {
			macroDefine:
				element.defineType // + element.definename.name + " = " + element.value
			VARSYM:
				element.name + " : " + getSizeStr((element.getContainerOfType(typeof(varnodedef))).size)
			SUBTABLESYM:
				element.name
			contextfielddef:
				getcontextfielddefText(element)
			fielddef:
				getfielddefText(element)
			subconstructor:
				doGetText(element.tableName) + ':'
			baseconstructor:
				':' + doGetText(element.print)
			constructprint:
				formatString(element.printpieces)
			constraint:
				doGetText(element.sym)
			DefineSym:
				getDefineSymText(element)
			default:
				super.doGetText(element)
		}
	}
	
	def getSizeStr(integerValue size) {
		if (size.value != null) {
			return size.value
		}
		if (size.sym != null) {
			return size.sym.getText
		}
		return "?"
	}

	def getBaseName(Object element) {
		element.class.name.substring(element.class.name.lastIndexOf('.') + 1)
	}

	def String formatString(EList<printpiece> list) {
		var str = "";
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
		str
	}

	override protected doGetImage(Object element) {
		// icons are stored in the 'icons' folder of this project.
		// when adding such a folder, don't forget to add it to the 'bin.includes' section in the build.properties
		switch element {
//			fielddef:
//				'F-blue.png'
//			contextfielddef:
//				'C-blue.png'
//			VARSYM:
//				'F-blue.png'
			default:
				super.doGetImage(element)
		}
	}
}

