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
class SleighMacroTest {

	@Inject extension ParseHelper<Model>
	@Inject extension ValidationTestHelper

	@Test def void testMacros() {
		var model = '''
			macro xyz(tom,dick,harry) {
				tom = dick;
				harry = tom;
				tom = 1;
			}
			
			macro ijk(do,wop) {
				do = 1;
				wop = 1;
			}
		'''.parse
		model.assertNoErrors
	}

	@Test def void testMacroReferences() {
		// Macro should have access to registers (globals)
		var model = '''
			define space register size=2 type=register_space wordsize=1 default;
			define register offset=0 size=1 [ Z ];
			
			macro a() {
				Z = 1;
			}
		'''.parse
		model.assertNoErrors
	}

	@Test def void testCrossedMacroRefs() {
		// Macro should not have cross parameter reference
		var model = '''
			macro xyz(tom,dick,harry) {
				tom = dick;
				harry = do;
			}
			
			macro ijk(do,wop) {
				do = 1;
				tom = wop;
			}
		'''.parse
		model.assertError(
			SleighPackage::eINSTANCE.getassignSym(),
			Diagnostic.LINKING_DIAGNOSTIC,
			"Couldn't resolve reference to lhsvarnode 'tom'."
		)
		model.assertError(
			SleighPackage::eINSTANCE.getexprSym(),
			Diagnostic.LINKING_DIAGNOSTIC,
			"Couldn't resolve reference to EObject 'do'."
		)
	}
}
