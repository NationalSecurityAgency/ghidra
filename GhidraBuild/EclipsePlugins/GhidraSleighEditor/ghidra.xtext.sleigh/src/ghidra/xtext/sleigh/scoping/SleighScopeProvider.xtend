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
package ghidra.xtext.sleigh.scoping


import com.google.common.base.Function
import com.google.common.base.Predicate
import java.util.ArrayList
import java.util.List
import org.eclipse.emf.ecore.EObject
import org.eclipse.emf.ecore.EReference
import org.eclipse.xtext.naming.QualifiedName
import org.eclipse.xtext.resource.IEObjectDescription
import org.eclipse.xtext.scoping.IScope
import org.eclipse.xtext.scoping.Scopes
import org.eclipse.xtext.scoping.impl.AbstractDeclarativeScopeProvider
import org.eclipse.xtext.scoping.impl.FilteringScope
import org.eclipse.xtext.scoping.impl.ScopeBasedSelectable
import org.eclipse.xtext.scoping.impl.SelectableBasedScope
import ghidra.xtext.sleigh.sleigh.LOCALSYM
import ghidra.xtext.sleigh.sleigh.aliasSym
import ghidra.xtext.sleigh.sleigh.assignSym
import ghidra.xtext.sleigh.sleigh.constraint
import ghidra.xtext.sleigh.sleigh.constructor
import ghidra.xtext.sleigh.sleigh.contextblock
import ghidra.xtext.sleigh.sleigh.contextentry
import ghidra.xtext.sleigh.sleigh.exportedSym
import ghidra.xtext.sleigh.sleigh.exprSym
import ghidra.xtext.sleigh.sleigh.globalLoc
import ghidra.xtext.sleigh.sleigh.macrodef
import ghidra.xtext.sleigh.sleigh.pexprSym
import ghidra.xtext.sleigh.sleigh.rtlbody
import ghidra.xtext.sleigh.sleigh.rtlmid
import ghidra.xtext.sleigh.sleigh.statement
import ghidra.xtext.sleigh.sleigh.xrtl

import static extension org.eclipse.xtext.EcoreUtil2.*

/**
 * This class contains custom scoping description.
 * 
 * See https://www.eclipse.org/Xtext/documentation/303_runtime_concepts.html#scoping
 * on how and when to use it.
 */
public class SleighScopeProvider extends AbstractDeclarativeScopeProvider {

	override getScope(EObject context, EReference ref) {
		//System.out.println(context.class.name + " - " + ref.name + " : ")
		var scope = super.getScope(context, ref)
		//System.out.println("        " + scope.toString)
		return scope
	}

	def IScope scope_assignSym_symref(assignSym context, EReference eReference) {
		var localScope = context.eContainer.symbolsDefinedBefore(context)
		var cont = context.getContainerOfType(typeof(rtlbody));
		var superscope = super.getDelegate().getScope(cont, eReference)
		return createFilteredLocalScope(superscope, localScope, eReference)
	}

	def IScope scope_exprSym_vnode(exprSym context, EReference eReference) {
		var localScope = context.eContainer.symbolsDefinedBefore(context)
		var cont = context.getContainerOfType(typeof(rtlbody));
		var superscope = super.getDelegate().getScope(cont, eReference)
		return createFilteredLocalScope(superscope, localScope, eReference)
	}

	def IScope scope_exportedSym_symref(exportedSym context, EReference eReference) {
		var localScope = context.eContainer.symbolsDefinedBefore(context)
		var cont = context.getContainerOfType(typeof(rtlbody));
		var superscope = super.getDelegate().getScope(cont, eReference)
		createFilteredLocalScope(superscope, localScope, eReference)
	}


	def IScope scope_pexprSym_sym(pexprSym context, EReference eReference) {
		var localScope = context.eContainer.symbolsDefinedBefore(context)
		var cont = context.getContainerOfType(typeof(constructor));
		var superscope = super.getDelegate().getScope(cont, eReference)
		createFilteredLocalScope(superscope, localScope, eReference)
	}


	def IScope scope_constraint_sym(constraint context, EReference eReference) {
		var cont = context.getContainerOfType(typeof(constructor));
		var superscope = super.getDelegate().getScope(cont, eReference)
	    var scope= createFilteredLocalScope(superscope, IScope.NULLSCOPE, eReference)
	    scope
	}

	def IScope scope_aliasSym_symref(aliasSym context, EReference eReference) {
		var cont = context.getContainerOfType(typeof(constructor));
		var localScope = printPieceScope(cont,IScope.NULLSCOPE);
		localScope
	}
	
	def IScope scope_contextentry_lhs(contextentry context, EReference eReference) {
		var cont = context.getContainerOfType(typeof(constructor));
		var localScope = printPieceScope(cont,IScope.NULLSCOPE);
		var superscope = super.getDelegate().getScope(cont, eReference)
		createFilteredLocalScope(superscope, localScope, eReference)
	}
	
	def IScope scope_globalLoc_tsym(globalLoc context, EReference eReference) {
		var cont = context.getContainerOfType(typeof(constructor));
		var localScope = printPieceScope(cont,IScope.NULLSCOPE);
		var superscope = super.getDelegate().getScope(cont, eReference)
		createFilteredLocalScope(superscope, localScope, eReference)
	}

	def IScope createFilteredLocalScope(IScope supscope, IScope localScope, EReference eReference) {
		var filtscope = new FilteringScope(supscope, new Predicate<IEObjectDescription>() {
			override apply(IEObjectDescription input) {
				val sym = input.getEObjectOrProxy()
				var notAliasOrLocal = !((sym instanceof LOCALSYM) || (sym instanceof aliasSym))
				return notAliasOrLocal
			}
		});

		// Do scope in reverse, aliasSyms are just and alias, choose global scope over alias
		// The global scope has all LOCALSYM and aliasSym filtered out.
		// This may not be the most efficient method, but works.
		// Also for LOCALSYM, a Global sym may shadow it.  Not quite right
		// Should really be (LOCALSYM, Global(outerscope), AliasSym)
		var scope = SelectableBasedScope.createScope(localScope, new ScopeBasedSelectable(filtscope),
			eReference.getEReferenceType(), false)
		scope
	}

	def dispatch IScope symbolsDefinedBefore(EObject context, EObject o) {
		context.eContainer.symbolsDefinedBefore(o)
	}

	def dispatch IScope symbolsDefinedBefore(macrodef context, EObject o) {
		Scopes::scopeFor(
			context.args.args,
			context.symbolsDefinedBefore(o.eContainer)
		)
	}

	def dispatch IScope symbolsDefinedBefore(constructor s, EObject o) {
		var scope = Scopes::scopeFor(s.eContents)
		printPieceScope(s,scope);
	}
	
	def dispatch IScope symbolsDefinedBefore(contextblock s, EObject o) {
		var scope = Scopes::scopeFor(s.eContents, s.eContainer.symbolsDefinedBefore(o.eContainer))
		var cont = s.getContainerOfType(typeof(constructor))
		printPieceScope(cont,scope);
	}

	def dispatch IScope symbolsDefinedBefore(rtlbody b, EObject o) {
		var scope = Scopes::scopeFor(
			b.body.statements.rtllist.variablesDeclaredBefore(o)
		)
		var cont = b.getContainerOfType(typeof(constructor));
		printPieceScope(cont,scope);
	}
	
	def dispatch IScope symbolsDefinedBefore(rtlmid b, EObject o) {
		return symbolsDefinedBefore(b.eContainer, o);
	}

	def dispatch IScope symbolsDefinedBefore(xrtl b, EObject o) {
		var syms = b.statements.rtllist.variablesDeclaredBefore(null);
		if (b.additionalStatements != null) {
			syms.addAll(b.additionalStatements.rtllist.variablesDeclaredBefore(null))
		}
		var scope = Scopes::scopeFor(syms)
		var cont = b.getContainerOfType(typeof(constructor));
		printPieceScope(cont,scope);
	}
	
	// Create a scope for all ID symbols in printpiece
	def printPieceScope(constructor cont, IScope outerScope) {
		if (cont == null) return outerScope
		var vars = cont.variablesDeclaredIn()
		var q = QualifiedName.wrapper(new Function<aliasSym, String>() {
			
			override apply(aliasSym input) {
				if (input == null) return null;
				input.sym
			}
		})
		var localScope = Scopes.scopeFor(vars, q, outerScope)
		localScope
	}

	// things in context block must be in printpieces
	def private variablesDeclaredIn(constructor b) {
		var iter = b.print.printpieces.iterator;
		var List<aliasSym> list = new ArrayList<aliasSym>();
		while (iter.hasNext) {
			var piece = iter.next;
			if (piece.sym instanceof aliasSym) {
				list.add(piece.sym)
			}
		}
		return list
	}

	def private variablesDeclaredBefore(List<statement> list, EObject o) {
		var end = list.size - 1;
		if (o != null) {
			end = list.indexOf(o);
		}
		val sublist = list.subList(0, end + 1);
		var iter = sublist.iterator;
		var List<LOCALSYM> locList = new ArrayList<LOCALSYM>();
		while (iter.hasNext) {
			var obj = iter.next;
			if (obj instanceof statement) {
				var stmt = obj as statement;
				if (stmt.lhs != null && stmt.lhs.local != null && stmt.lhs.local.sym instanceof LOCALSYM) {
					locList.add(stmt.lhs.local.sym as LOCALSYM);
				}
				if (stmt.ldef != null && stmt.ldef.sym instanceof LOCALSYM) {
					locList.add(stmt.ldef.sym as LOCALSYM);
				}
			}
		}
		return locList;
	}
}
