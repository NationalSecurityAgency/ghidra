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
import org.eclipse.xtext.testing.InjectWith
import org.eclipse.xtext.testing.extensions.InjectionExtension
import org.eclipse.xtext.testing.util.ParseHelper
import org.eclipse.xtext.testing.validation.ValidationTestHelper
import ghidra.xtext.sleigh.sleigh.Model
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.^extension.ExtendWith

@ExtendWith(InjectionExtension)
@InjectWith(SleighInjectorProvider)
class SleighParsingTest {

	@Inject
	ParseHelper<Model> parseHelper

	@Inject extension ValidationTestHelper
	
	@Test def void testEndian() {
		var model = parseHelper.parse('''
		define endian= big;
		''')
		model.assertNoErrors
		
		model = parseHelper.parse('''
		define endian= little;
		''')
		model.assertNoErrors
		
		
		model = parseHelper.parse('''
		define endian= little;
		''')
		
	}
	
	@Test def void macroUse() {
		var model = parseHelper.parse('''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V
						@if ENDIAN == "little"
			EF
			@else
			BF
			@endif
			];
			
			define register offset=100 size=1 [ contReg
			@if defined(ENDIAN)
			ifReg
			@endif
			];
			
			define token instr(16)
			   op = (0,15)
			@if ENDIAN == "big"
			   reg = (0,1)
			@endif
			   cc = (2,3)
			@else
			;
			
			define context contReg
				contFlag = (0,0)
				;
			
			attach variables [ reg ] [ Z C N V
			@if ENDIAN == "little"
			EF
			@else
			BF
			@endif
			];
			
			macro a(arg1,arg2) {
				local foo = 1;
			@if defined(ENDIAN)
				foo = (~foo & foo | foo) << foo;
			@endif
				Z = 1;
				arg1 = 3;
				arg2 = foo;
			}
			
			CC: "ne" is cc=0x1 { local tmp = !Z; C = 1; tmp = C; export tmp; }
			CC: "lt" is cc=0x2 { local tmp = N != V; export tmp; }
			CC: "lt" is cc=0x2 { local tmp:1 = N != V; export tmp; }
			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; }
			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; tmp = 1; }
			
			:mov reg,N,op is op=0 & CC & N & reg & op & op=1
			{ tmp:1 = CC;
			@if defined(ENDIAN)
			reg = tmp;
			@endif
			@if ENDIAN != "big"
			reg = N;
			@endif
			}
			
			Dest: loc is op=0 [ loc = inst_next; ] { export loc; }
			:jmp Dest is Dest { call Dest; }
			
			:set reg is contFlag=0 & op=0 [ contFlag = 1; ] {}	
		''')
		model.assertNoErrors
	}
	
	@Test def void testWith() {
		var model = parseHelper.parse('''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z C N V
						@if ENDIAN == "little"
			EF
			@else
			BF
			@endif
			];
			
			define register offset=100 size=1 [ contReg
			@if defined(ENDIAN)
			ifReg
			@endif
			];
			
			define token instr(16)
			   op = (0,15)
			@if ENDIAN == "big"
			   reg = (0,1)
			@endif
			   cc = (2,3)
			@else
			;
			
			define context contReg
				contFlag = (0,0)
				;
			
			attach variables [ reg ] [ Z C N V
			@if ENDIAN == "little"
			EF
			@else
			BF
			@endif
			];
			
			macro a(arg1,arg2) {
				local foo = 1;
			@if defined(ENDIAN)
				foo = (~foo & foo | foo) << foo;
			@endif
				Z = 1;
				arg1 = 3;
				arg2 = foo;
			}
			
			with CC : cc=0x1 {
			CC: "ne" is cc=0x1 { local tmp = !Z; C = 1; tmp = C; export tmp; }
			CC: "lt" is cc=0x2 { local tmp = N != V; export tmp; }
			CC: "lt" is cc=0x2 { local tmp:1 = N != V; export tmp; }
			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; }
			CC: "lt" is cc=0x2 {       tmp:1 = N != V; export tmp; tmp = 1; }
			}
			
			:mov reg,N,op is op=0 & CC & N & reg & op & op=1
			{ tmp:1 = CC;
			@if defined(ENDIAN)
			reg = tmp;
			@endif
			  tmp = popcount(CC);
			}
			
			Dest: loc is op=0 [ loc = inst_next; ] { export loc; }
			:jmp Dest is Dest { call Dest; }
			
			:set reg is contFlag=0 & op=0 [ contFlag = 1; ] {}	
		''')
		model.assertNoErrors
	}
}

