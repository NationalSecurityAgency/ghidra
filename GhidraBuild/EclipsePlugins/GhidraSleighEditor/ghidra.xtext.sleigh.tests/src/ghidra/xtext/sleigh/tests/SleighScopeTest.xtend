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
package ghidra.xtext.sleigh.tests

import com.google.inject.Inject
import com.google.inject.Provider
import org.eclipse.emf.ecore.util.EcoreUtil
import org.eclipse.xtext.diagnostics.Diagnostic
import org.eclipse.xtext.resource.XtextResourceSet
import org.eclipse.xtext.testing.InjectWith
import org.eclipse.xtext.testing.extensions.InjectionExtension
import org.eclipse.xtext.testing.util.ParseHelper
import org.eclipse.xtext.testing.validation.ValidationTestHelper
import ghidra.xtext.sleigh.sleigh.Model
import ghidra.xtext.sleigh.sleigh.SleighPackage
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.^extension.ExtendWith

@ExtendWith(InjectionExtension)
@InjectWith(SleighInjectorProvider)
class SleighScopeTest {

	@Inject extension ParseHelper<Model> parser
	@Inject extension ValidationTestHelper validationTester
	
	@Inject
	private Provider<XtextResourceSet> resourceSetProvider;
	
// Sample to use for testing
//		var model = '''
//			define space register size=2 type=register_space wordsize=1 default;
//			define register offset=0 size=1 [ Z C N V ];
//			
//			define token instr(16)
//			   op = (0,15)
//			   reg = (0,1)
//			   cc = (2,3)
//			;
//			
//			attach variables [ reg ] [ Z C N V ];
//			
//			macro a() {
//				Z = 1;
//			}
//			
//			CC: "ne" is cc=0x1 { local tmp = !Z; C = 1; tmp = C; export tmp; }
//			CC: "lt" is cc=0x2 { local tmp = N != V; export tmp; }
//			CC: "lt" is cc=0x2 { local tmp:1 = N != V; export tmp; }
//			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; }
//			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; tmp = 1; }
//			
//			:mov reg,N is op=0 & CC & N & reg { tmp:1 = CC; reg = tmp; }
//		'''.parse

	@Test def void testReferences() {		
		// tmp should not resolve
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			attach variables [ reg ] [ Z C N V ];
			
			:mov reg,N is op=0 & C & N & reg { tmp:1 = 1; }
						
			:mov reg,N is op=0 & C & N & reg { tmp = C; }
		'''.parse
		
		assertError(model,
			SleighPackage::eINSTANCE.getassignSym(),
			Diagnostic.LINKING_DIAGNOSTIC, 311, 3, 
			"Couldn't resolve reference to lhsvarnode 'tmp'."
		)
		
		// tmp should not resolve
		model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			attach variables [ reg ] [ Z C N V ];
			
			:mov reg,N is op=0 & C & N & reg { tmp:1 = 1; }
			
			:mov reg,N is op=0 & C & N & reg { reg = tmp; }
		'''.parse
		
		assertError(model,
			SleighPackage::eINSTANCE.getexprSym(),
			Diagnostic.LINKING_DIAGNOSTIC, 314, 3, 
			"Couldn't resolve reference to EObject 'tmp'."
		)
	}
	
	@Test def void testMacroReferences() {
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			attach variables [ reg ] [ Z C N V ];
			
			macro macro_a(arg1,arg2) {
				local foo = 1;
				foo = (~foo & foo | foo) << foo;
				Z = 1;
				arg1 = 3;
				arg2 = foo;
			}
			
			:mov reg,N,op is op=0 & N & reg & op & op=1 {
				tmp:1 = 1;
				tmp2:1 = reg(4);
				macro_a(reg,tmp);
			}
		'''.parse
		model.assertNoErrors
	}
	
	
	@Test def void testBadAliasReferences() {
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			:mov AliasRef is op=0 & AliasRef [ AliasRef = inst_next; ] { tmp:1 = AliasRef; } #AliasRef in constraint
		'''.parse
		
		assertError(model,
			SleighPackage::eINSTANCE.getconstraint(),
			Diagnostic.LINKING_DIAGNOSTIC, 164,8, 
			"Couldn't resolve reference to EObject 'AliasRef'."
		)
		
		model = '''
			define space register size=2 type=register_space wordsize=1 default;
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			AliasRef: "empty" is op=0 {}
			
			:mov AliasRef is op=0 [ AliasRef = inst_next; ] { tmp:1 = AliasRef; } #AliasRef in constraint
		'''.parse
		
		var references = EcoreUtil.UsageCrossReferencer.find(model.elements)
		
		references.forEach[p1, p2 |
			System.out.println(p1 + " -> " + p2)
		]
	}
	
	@Test def void testAliasRefOverrid() {
		
		var XtextResourceSet resourceSet = resourceSetProvider.get();
		
		parser.parse("REGGsrc: reg is reg { export reg; } ", resourceSet)
		
		var model = parser.parse('''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			define register offset=100 size=1 [ contReg ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			define context contReg
				contFlag = (0,0)
				;
			
			attach variables [ reg ] [ Z C N V ];
			
			macro a(arg1,arg2) {
				local foo = 1;
				foo = (~foo & foo | foo) << foo;
				Z = 1;
				arg1 = 3;
				arg2 = foo;
			}
			
			CC: "ne" is cc=0x1 { local tmp = !Z; C = 1; tmp = C; export tmp; }
			CC: "lt" is cc=0x2 { local tmp = N != V; export tmp; }
			CC: "lt" is cc=0x2 { local tmp:1 = N != V; export tmp; }
			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; }
			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; tmp = 1; }
			
			:mov reg,N,op is op=0 & CC & N & reg & op & op=1 { tmp:1 = CC; reg = tmp; }
			
			:mov REGGsrc,N,op is op=0 & CC & N & reg & REGGsrc & op & op=1 { REGGsrc = op; }
			
			Dest: loc is op=0 [ loc = inst_next; ] { export loc; }
			:jmp Dest is Dest { call Dest; }
			
			:set reg is contFlag=0 & op=0 [ contFlag = 1; ] {}
		''', resourceSet)
		model.assertNoErrors;

		var references = EcoreUtil.UsageCrossReferencer.find(model.elements)
		
		references.forEach[p1, p2 |
			System.out.println(p1 + " -> " + p2)
		]

		
//		
//		model.eAllContents.filter[elem |
//			elem instanceof SUBTABLESYM
//		].forEach[
//			elem | var list = elem.eCrossReferences; System.out.println(list)
//		]
//		
//		// now need to verify xref of reg,N,op are not aliases in the match or pcode
//		var refs = model.eCrossReferences;
//		refs.forEach[
//			element | println(element);
//		]
//		
		// need to verify that an alias in the context var stays as an alias var
		// unless it is also a global symbol
	}
	
		@Test def void testContextAliasRef() {
		
		var XtextResourceSet resourceSet = resourceSetProvider.get();
		
		parser.parse("REGGsrc: reg is reg { export reg; } ", resourceSet)
		
		var model = parser.parse('''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			define register offset=100 size=1 [ contReg ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			define context contReg
				contFlag = (0,0)
				cont2 = (1,1)
				;
			
			attach variables [ reg ] [ Z C N V ];
			
			
			#:mov reg,N,op,vis is op=0 & N & reg & op & op=1 [ vis = op << 20; ] { tmp:1 = vis reg = tmp; }

			#:mov reg,N,op,vis is op=0 & N & reg & op & op=1 [ vis = op << 20; contFlag=op; cont2=contFlag; ] { tmp:1 = vis; reg = tmp; }

			:mov reg,vis is op=0 & reg [ vis = 20; contFlag=vis; ] { tmp:1 = vis; reg = tmp; }
			
		''', resourceSet)
		model.assertNoErrors;

		var references = EcoreUtil.UsageCrossReferencer.find(model.elements)
		
		references.forEach[p1, p2 |
			System.out.println(p1 + " -> " + p2)
		]
	}
}