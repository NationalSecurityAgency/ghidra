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
package ghidra.xtext.sleigh.ide

import com.google.inject.Guice
import ghidra.xtext.sleigh.SleighRuntimeModule
import ghidra.xtext.sleigh.SleighStandaloneSetup
import org.eclipse.xtext.util.Modules2

/**
 * Initialization support for running Xtext languages as language servers.
 */
class SleighIdeSetup extends SleighStandaloneSetup {

	override createInjector() {
		Guice.createInjector(Modules2.mixin(new SleighRuntimeModule, new SleighIdeModule))
	}
	
}
