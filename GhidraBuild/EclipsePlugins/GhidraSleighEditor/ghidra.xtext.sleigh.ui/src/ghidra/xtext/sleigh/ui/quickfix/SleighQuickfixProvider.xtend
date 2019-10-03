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
package ghidra.xtext.sleigh.ui.quickfix

import org.eclipse.emf.ecore.EObject
import org.eclipse.emf.ecore.util.EcoreUtil
import org.eclipse.xtext.EcoreUtil2
import org.eclipse.xtext.diagnostics.Diagnostic
import org.eclipse.xtext.resource.XtextResource
import org.eclipse.xtext.ui.editor.quickfix.DefaultQuickfixProvider
import org.eclipse.xtext.ui.editor.quickfix.Fix
import org.eclipse.xtext.ui.editor.quickfix.IssueResolutionAcceptor
import org.eclipse.xtext.util.concurrent.IUnitOfWork
import org.eclipse.xtext.validation.Issue
import ghidra.xtext.sleigh.sleigh.Expression
import ghidra.xtext.sleigh.sleigh.LOCALSYM
import ghidra.xtext.sleigh.sleigh.Model
import ghidra.xtext.sleigh.sleigh.SleighFactory
import ghidra.xtext.sleigh.sleigh.VARSYM
import ghidra.xtext.sleigh.sleigh.constraint
import ghidra.xtext.sleigh.sleigh.constructor
import ghidra.xtext.sleigh.sleigh.exprSym
import ghidra.xtext.sleigh.sleigh.fielddef
import ghidra.xtext.sleigh.sleigh.integerValue
import ghidra.xtext.sleigh.sleigh.lhsvarnode
import ghidra.xtext.sleigh.sleigh.localDefine
import ghidra.xtext.sleigh.sleigh.macroOrPcode
import ghidra.xtext.sleigh.sleigh.statement
import ghidra.xtext.sleigh.sleigh.tokendef
import ghidra.xtext.sleigh.sleigh.varattach
import ghidra.xtext.sleigh.sleigh.varnodedef
import ghidra.xtext.sleigh.sleigh.vnoderef

import static extension org.eclipse.emf.ecore.util.EcoreUtil.*
import static extension org.eclipse.xtext.EcoreUtil2.*

/**
 * Custom quickfixes.
 *
 * See https://www.eclipse.org/Xtext/documentation/310_eclipse_support.html#quick-fixes
 */
class SleighQuickfixProvider extends DefaultQuickfixProvider {

	@Fix(Diagnostic::LINKING_DIAGNOSTIC)
	def void createMissingVariable(Issue issue, IssueResolutionAcceptor acceptor) {
		var message = issue.message;
		var to = getToName(message);
		var linkName = getLinkName(message);
		var sname = macroOrPcode.simpleName.toString();
		switch (to) {
			case macroOrPcode.simpleName:
				missingPseudoOp(issue, acceptor, to, linkName)
			case lhsvarnode.simpleName:
				createLocalVarnode(issue, acceptor, to, linkName)
			case EObject.simpleName:
				missingEObjectLink(issue, acceptor, to, linkName)
		}
	}

	def missingPseudoOp(Issue issue, IssueResolutionAcceptor acceptor, String to, String linkName) {
		acceptor.accept(
			issue,
			"Create pcodeop '" + linkName + "'",
			"Create pcodeop '" + linkName + "'",
			"",
			[ element, context |
				val currentEntity = EcoreUtil2.getContainerOfType(element,constructor)
				val model = currentEntity.eContainer as Model
				val newdef = SleighFactory::eINSTANCE.createpcodeopdef() => [
					ops.add(SleighFactory::eINSTANCE.createUSEROPSYM() => [
						name = context.xtextDocument.get(issue.offset, issue.length)
					])
				];
				model.elements.add(model.elements.indexOf(currentEntity), newdef)
			]
		);
	}

	def missingEObjectLink(Issue issue, IssueResolutionAcceptor acceptor, String to, String linkName) {
		val modificationContext = getModificationContextFactory().createModificationContext(issue);
		val xtextDocument = modificationContext.getXtextDocument();
		xtextDocument.readOnly(
			new IUnitOfWork.Void<XtextResource>() {

				override process(XtextResource state) throws Exception {
					var cause = state.getResourceSet().getEObject(issue.getUriToProblem(), false);
					if (cause instanceof constraint) {
						missingConstraint(issue, acceptor, to, linkName, cause)
						missingSubConstructor(issue, acceptor, to, linkName, cause)
					}
//				switch cause {
//					case constraint:
//						
//					default: {
//						var x = cause
//					}
//				}
				}
			}
		)
	}

	def missingConstraint(Issue issue, IssueResolutionAcceptor acceptor, String to, String linkName, EObject cause) {
		acceptor.accept(
			issue,
			"Create fieldef '" + linkName + "'",
			"Create fieldef '" + linkName + "'",
			"",
			[ element, context |
				var root = EcoreUtil2.getRootContainer(cause) as Model;
				// find fielddef
				var tokendefs = root.getAllContentsOfType(typeof(tokendef))
				if(tokendefs.size <= 0) return;
				var tokendef = tokendefs.get(0);

				// if found, put at end
				val newfielddef = SleighFactory::eINSTANCE.createfielddef() => [
					name = linkName
					// TODO: try to figure out start/end
					// TODO: ask start / end
					start = SleighFactory.eINSTANCE.createintegerValue() => [
						value = '0';
					]
					end = SleighFactory.eINSTANCE.createintegerValue() => [
						value = '0';
					]
				];
				// add
				tokendef.fields.tokens.add(newfielddef)
			]
		);
	}
	
	def missingSubConstructor(Issue issue, IssueResolutionAcceptor acceptor, String to, String linkName, EObject cause) {
		acceptor.accept(
			issue,
			"Create SubConstruct '" + linkName + "'",
			"Create SubConstruct '" + linkName + "'",
			"",
			[ element, context |
				var model = cause.rootContainer as Model;

				var container = EcoreUtil2.getContainerOfType(cause, constructor)
				
				// create subconstructor template
				val sub = SleighFactory::eINSTANCE.createsubconstructor() => [
					tableName = SleighFactory.eINSTANCE.createSUBTABLESYM() => [
								name = linkName;
							]
					print = SleighFactory.eINSTANCE.createconstructprint() => [
						var pp = SleighFactory.eINSTANCE.createprintpiece() => [
							str = ""
						]
						printpieces.add(pp)
						is = SleighFactory.eINSTANCE.createisKeyword() => []
					]
					match = SleighFactory.eINSTANCE.createpequation() => [
						constraints = SleighFactory.eINSTANCE.createconstraint() => [
								isepsilon = true
						]
					]
					body = SleighFactory.eINSTANCE.creatertlbody() => [
						unimpl = true
					]
				];
				// add before this instance
				model.elements.add(model.elements.indexOf(container), sub)
			]
		);
	}

	def createLocalVarnode(Issue issue, IssueResolutionAcceptor acceptor, String to, String linkName) {
		acceptor.accept(
			issue,
			"Create local '" + linkName + "'",
			"Create local '" + linkName + "'",
			"",
			[ element, context |
				// find size of first element if it can
				val s = findElementSize(element);
				if (s == null) {
					val newdef = SleighFactory::eINSTANCE.createassignSym() => [
						local = SleighFactory::eINSTANCE.createlocalDefine() => [
							sym = SleighFactory.eINSTANCE.createLOCALSYM() => [
								name = linkName;
							]
						]
					];
					element.replace(newdef);
				} else {
					val newdef = SleighFactory::eINSTANCE.createassignSym() => [
						local = SleighFactory::eINSTANCE.createlocalDefine() => [
							sym = SleighFactory.eINSTANCE.createLOCALSYM() => [
								name = linkName;
							]
							size = SleighFactory.eINSTANCE.createintegerValue() => [
								value = s.value;
								sym = s.sym;
							]
						]
					];
					element.replace(newdef);
				}
			]
		);
	}

	def integerValue findElementSize(EObject element) {
		val currentEntity = EcoreUtil2.getContainerOfType(element, statement)
		val rhs = currentEntity.rhs;
		val s = findSize(rhs);
		return s;
	}

	var integerValue len;

	def integerValue findSize(Expression rhs) {
		len = null;
		if (rhs instanceof exprSym) {
			return getExprSymLength(rhs);
		}
		var vlist = rhs.getAllContentsOfType(typeof(exprSym));
		vlist.forEach [ it |
			getExprSymLength(it)
		]
		return len;
	}

	def getExprSymLength(exprSym sym) {
		var node = sym.vnode;
		switch node {
			VARSYM: {
				var def = node.getContainerOfType(typeof(varnodedef));
				if (def != null && def.size != null) {
					if (len == null) {
						len = def.size;
					}
				} else if (len != def.size) {
					len = null;
				}
			}
			fielddef: {
				len = findVarAttachLen(node);
			}
			LOCALSYM: {
				var ldef = node.getContainerOfType(typeof(localDefine));
				if (ldef != null && ldef.size != null) {
					if (len == null) {
						len = ldef.size;
					}
				} else if (len != ldef.size) {
					len = null;
				}
			}
		}
	}

	def integerValue findVarAttachLen(fielddef fdef) {
		// find all var attaches and display possible names
		var model = fdef.eResource.contents.get(0);
		var varatt = model.eAllContents.filter(typeof(varattach));
		while (varatt.hasNext) {
			var next = varatt.next;
			var vlist = next.valuelist.valuelist.listIterator;
			while (vlist.hasNext) {
				var v = vlist.next;
				if (v.sym.equals(fdef)) {
					var viter = next.vlist.varDefList.iterator;
					while (viter.hasNext) {
						var varname = viter.next;
						var vref = varname.varpart;
						if (vref != null) {
							var vdef = vref.getContainerOfType(typeof(varnodedef));
							if (vdef != null) {
								var size = vdef.size;
								return size;
							}
						}
					}
				}
			}

		}
		return null;
	}

	def findVnodeSize(vnoderef ref) {
		System.out.println('  printit ' + ref.ID);
	}

	def String getLinkName(String str) {
		var end = str.lastIndexOf('\'')
		var start = str.lastIndexOf('\'', end - 1)
		return str.substring(start + 1, end)
	}

	def String getToName(String str) {
		val refString = "reference to ";

		var index = str.indexOf(refString);
		if (index == -1) {
			return null;
		}
		var start = index + refString.length;
		var refStr = str.substring(start);
		refStr = refStr.substring(0, refStr.indexOf(' '));
		return refStr;
	}

}
