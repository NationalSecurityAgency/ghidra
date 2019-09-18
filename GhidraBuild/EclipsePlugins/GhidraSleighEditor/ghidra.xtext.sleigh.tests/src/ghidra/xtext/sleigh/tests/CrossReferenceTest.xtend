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
import org.eclipse.xtext.diagnostics.Diagnostic
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
class CrossReferenceTest {

	@Inject extension ParseHelper<Model>
	@Inject extension ValidationTestHelper

	@Test def void testReferences() {
		// Macro should have access to registers (globals)
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			attach variables [ reg ] [ Z C N V ];
			
			:mov reg,N is op=0 & N & reg {
			<label1>
				tmp:1 = N;
				if (tmp == 0) goto <label1>;
				reg = tmp;
			}
			
			:mov reg,N is op=0 & N & reg {
				tmp = N;   # tmp should not resolve
			}
		'''.parse
		// model.assertNoErrors
		// temp should not resolve
		model.assertError(
			SleighPackage::eINSTANCE.getassignSym(),
			Diagnostic.LINKING_DIAGNOSTIC,
			353,
			3,
			"tmp"
		)
	}

	@Test def void testCrossbuildReferences() {
		// Macro should have access to registers (globals)
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V pc ];
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			attach variables [ reg ] [ Z C N V ];
			
			CrossbuildAddr0: loc  is epsilon [ loc = inst_start; ]             { export *:4 loc; }

			Parallel32: "" is op=0x0 & CrossbuildAddr0 {
				crossbuild CrossbuildAddr0,COMMIT;
				crossbuild CrossbuildAddr0,LOOP;
			}

			:^instruction is cc=0x1 & instruction {
				build instruction;
			  <<LOOP>>
				pc = 0;
				goto [pc];
			}

			:L is op=0x999 {
				build Parallel32;
			  <<COMMIT>>
			    pc = 0;
			}
		'''.parse
		model.assertNoErrors
	}
	
	
	@Test def void testSubPieceReferences() {
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V ];
			define register offset=0 size=4 [ BR ];
			
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
				tmp2:2 = BR:2;
				tmp2:2 = BR(2);
				tmp2:2 = reg:2;
			}
		'''.parse
		model.assertNoErrors
	}
	
	@Test def void testglobalsetReferences() {
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V contextreg ];
			define register offset=0 size=4 [ BR ];
			
			define context contextreg
  				TMode		 = (0,0)
			;
			
			define token instr(16)
			   op = (0,15)
			   reg = (0,1)
			   cc = (2,3)
			;
			
			attach variables [ reg ] [ Z C N V ];
					
			GS: reloff		is op=100
  			[ reloff = inst_start + 8; TMode=1; globalset(reloff,TMode); globalset(inst_next,TMode); ]
			{
  				export *:4 reloff;
			}
			
		'''.parse
		model.assertNoErrors
	}	
}