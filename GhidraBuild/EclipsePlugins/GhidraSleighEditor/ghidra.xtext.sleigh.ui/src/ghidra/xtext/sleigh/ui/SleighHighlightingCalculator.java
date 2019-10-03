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
package ghidra.xtext.sleigh.ui;

import static org.eclipse.xtext.ui.editor.syntaxcoloring.DefaultHighlightingConfiguration.COMMENT_ID;
import static org.eclipse.xtext.ui.editor.syntaxcoloring.DefaultHighlightingConfiguration.KEYWORD_ID;
import static ghidra.xtext.sleigh.ui.SleighHighlightingConfiguration.CONTEXTFIELD;
import static ghidra.xtext.sleigh.ui.SleighHighlightingConfiguration.LOCAL;
import static ghidra.xtext.sleigh.ui.SleighHighlightingConfiguration.PRINTPIECE;
import static ghidra.xtext.sleigh.ui.SleighHighlightingConfiguration.SUBTABLE;
import static ghidra.xtext.sleigh.ui.SleighHighlightingConfiguration.TOKENFIELD;
import static ghidra.xtext.sleigh.ui.SleighHighlightingConfiguration.VARIABLE;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.xtext.CrossReference;
import org.eclipse.xtext.impl.TerminalRuleImpl;
import org.eclipse.xtext.nodemodel.BidiIterator;
import org.eclipse.xtext.nodemodel.BidiTreeIterator;
import org.eclipse.xtext.nodemodel.INode;
import org.eclipse.xtext.nodemodel.impl.HiddenLeafNode;
import org.eclipse.xtext.nodemodel.impl.LeafNode;
import org.eclipse.xtext.resource.XtextResource;
import org.eclipse.xtext.util.CancelIndicator;
import org.eclipse.xtext.ide.editor.syntaxcoloring.DefaultSemanticHighlightingCalculator;
import org.eclipse.xtext.ide.editor.syntaxcoloring.IHighlightedPositionAcceptor;

import ghidra.xtext.sleigh.sleigh.CONTEXTSYM;
import ghidra.xtext.sleigh.sleigh.LOCALSYM;
import ghidra.xtext.sleigh.sleigh.SUBTABLESYM;
import ghidra.xtext.sleigh.sleigh.TOKENSYM;
import ghidra.xtext.sleigh.sleigh.VARSYM;
import ghidra.xtext.sleigh.sleigh.aliasSym;
import ghidra.xtext.sleigh.sleigh.anysymbol;
import ghidra.xtext.sleigh.sleigh.assignSym;
import ghidra.xtext.sleigh.sleigh.constraint;
import ghidra.xtext.sleigh.sleigh.exprSym;
import ghidra.xtext.sleigh.sleigh.fielddef;
import ghidra.xtext.sleigh.sleigh.isKeyword;
import ghidra.xtext.sleigh.sleigh.pexprSym;
import ghidra.xtext.sleigh.sleigh.printpiece;
import ghidra.xtext.sleigh.sleigh.valuepart;
import ghidra.xtext.sleigh.sleigh.varpart;

public class SleighHighlightingCalculator extends DefaultSemanticHighlightingCalculator {

	@Override
	public void provideHighlightingFor(XtextResource resource, IHighlightedPositionAcceptor acceptor,
			CancelIndicator cancelIndicator) {

		if (resource == null || resource.getParseResult() == null)
			return;

		super.provideHighlightingFor(resource, acceptor, cancelIndicator);
		
		INode root = resource.getParseResult().getRootNode();
		BidiTreeIterator<INode> it = root.getAsTreeIterable().iterator();
		while (it.hasNext()) {
			INode node = it.next();
			EObject grammarElement = node.getGrammarElement();
			EObject semanticElement = node.getSemanticElement();
			printNodeInfo(node, grammarElement, semanticElement);
			
//			if (node instanceof CompositeNodeWithSemanticElement
//					&& semanticElement instanceof contextfielddef) {
//				setStyles(acceptor, it, CONTEXTFIELD, "GROUP", CONTEXTFIELD);
//				setStyles(acceptor, node.getAsTreeIterable().reverse()
//						.iterator(), null, CONTEXTFIELD);
//			} else
			if (semanticElement instanceof VARSYM) {
				setNodeStyle(acceptor, node, VARIABLE);
//			} else if (grammarElement instanceof Keyword) {
//				setStyles(acceptor, it, KEYWORD_ID);
			} else if (semanticElement instanceof CONTEXTSYM) {
				setNodeStyle(acceptor, node, CONTEXTFIELD);
			} else if (semanticElement instanceof LOCALSYM) {
				setNodeStyle(acceptor, node, LOCAL);
			} else if (semanticElement instanceof TOKENSYM) {
				setNodeStyle(acceptor, node, TOKENFIELD);
			} else if (semanticElement instanceof fielddef) {
				setNodeStyle(acceptor, node, TOKENFIELD);
			} else if (semanticElement instanceof anysymbol) {
				setStyle(acceptor, node, semanticElement);
			} else if (grammarElement instanceof CrossReference) {
				CrossReference defn = (CrossReference) grammarElement;
				EObject semElem = semanticElement;
				if (semElem instanceof varpart || semElem instanceof valuepart) {
					setNodeStyle(acceptor, node, VARIABLE);
				} else if (semElem instanceof LOCALSYM) {
					setNodeStyle(acceptor, node, LOCAL);
				} else if (semElem instanceof exprSym) {
					exprSym sym = (exprSym) semElem;
					EObject vnode = sym.getVnode();
					if (vnode != null) {
						setStyle(acceptor, node, vnode);	
					} else {
						// System.out.println("  exprSym--" + semElem);
					}
				} else if (semElem instanceof assignSym) {
					// TODO: Causing a lazy linking error sometimes
					//    Possibly something wrong with the grammer for [lhsvarnode]
					// ERROR org.eclipse.xtext.linking.lazy.LazyLinkingResource  - An element of type ghidra.xtext.sleigh.sleigh.impl.aliasSymImpl is not assignable to the reference assignSym.symref
					assignSym sym = (assignSym) semElem;
					EObject vnode = sym.getSymref();
					if (vnode != null) {
						setStyle(acceptor, node, vnode);	
					} else {
						// System.out.println("  exprSym--" + semElem);
					}
				}
				else if (semElem instanceof constraint) {
					constraint sym = (constraint) semElem;
					EObject vnode = sym.getSym();
					if (vnode != null) {
						setStyle(acceptor, node, vnode);	
					} else {
						// System.out.println("  exprSym--" + semElem);
					}
				}
				else if (semElem instanceof pexprSym) {
					pexprSym sym = (pexprSym) semElem;
					EObject vnode = sym.getSym();
					if (vnode != null) {
						setStyle(acceptor, node, vnode);	
					} else {
						// System.out.println("  exprSym--" + semElem);
					}
				}
				else if (semElem instanceof aliasSym) {
					System.out.println("  semElem="+semElem);
				}
				else {
					// System.out.println("  semElem="+semElem);
				}
			} else if (semanticElement instanceof isKeyword) {
				setStyles(acceptor, it, KEYWORD_ID);
			} else if (semanticElement instanceof aliasSym && semanticElement.eContainer() instanceof printpiece) {
				setStyles(acceptor, it, PRINTPIECE);
			} else if (semanticElement instanceof printpiece) {
				setStyles(acceptor, it, PRINTPIECE);
			} else if (node instanceof HiddenLeafNode
					&& grammarElement instanceof TerminalRuleImpl) {
				processHiddenNode(acceptor, (HiddenLeafNode) node);
			}
			

		}
	}

	private void setStyle(IHighlightedPositionAcceptor acceptor, INode n, EObject vnode) {
		if (vnode instanceof LOCALSYM) {
			setNodeStyle(acceptor, n, LOCAL);
		} else if (vnode instanceof VARSYM) {
			setNodeStyle(acceptor, n, VARIABLE);
		} else if (vnode instanceof SUBTABLESYM) {
			setNodeStyle(acceptor, n, SUBTABLE);
		} else if (vnode instanceof fielddef) {
			setNodeStyle(acceptor, n, TOKENFIELD);
		} else {
			// System.out.println("  symtype = " + vnode);
		}
	}

	private void setNodeStyle(IHighlightedPositionAcceptor acceptor, INode n, String styleName) {
		acceptor.addPosition(n.getOffset(), n.getLength(), styleName);
	}

	private void printNodeInfo(INode node, EObject grammarElement,
			EObject semanticElement) {
		String grammar = "<no-grammar>";
		String semantic = "<no-semantic>";
		
		if (grammarElement != null) {
			grammar = grammarElement.getClass().getSimpleName();
		}
		if (semanticElement != null) {
			semantic = semanticElement.getClass().getSimpleName();
		}
		if (grammarElement instanceof TerminalRuleImpl) return;
		if (! (node instanceof LeafNode)) return;
//		 System.err.println( "Node: " + node.getClass().getSimpleName() +
//		 "\t\t\t\t" + grammar + " =\t\t\t\t" + semantic + "\"" + node.getText() + "\"");
	}

	void setStyles(IHighlightedPositionAcceptor acceptor,
			BidiIterator<INode> it, String... styles) {
		for (String s : styles) {
			if (!it.hasNext())
				return;
			INode n = skipWhiteSpace(acceptor, it);
			if (n != null && s != null)
				acceptor.addPosition(n.getOffset(), n.getLength(), s);
		}
	}

	INode skipWhiteSpace(IHighlightedPositionAcceptor acceptor,
			BidiIterator<INode> it) {
		INode n = null;
		while (it.hasNext()
				&& (n = it.next()).getClass() == HiddenLeafNode.class)
			processHiddenNode(acceptor, (HiddenLeafNode) n);
		return n;
	}

	INode skipWhiteSpaceBackwards(IHighlightedPositionAcceptor acceptor,
			BidiIterator<INode> it) {
		INode n = null;
		while (it.hasPrevious()
				&& (n = it.previous()).getClass() == HiddenLeafNode.class)
			processHiddenNode(acceptor, (HiddenLeafNode) n);
		return n;
	}

	void processHiddenNode(IHighlightedPositionAcceptor acceptor,
			HiddenLeafNode node) {
		if (node.getGrammarElement() instanceof TerminalRuleImpl) {
			TerminalRuleImpl ge = (TerminalRuleImpl) node.getGrammarElement();
			String name = ge.getName();
			if (name.equalsIgnoreCase("PDL_COMMENT") || name.equalsIgnoreCase("ML_COMMENT") || name.equalsIgnoreCase("SL_COMMENT")) {
				acceptor.addPosition(node.getOffset(), node.getLength(), COMMENT_ID);
			}
		}

	}

}
