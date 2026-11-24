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
package ghidra.app.plugin.core.analysis.rust.demangler;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledObject;

public class RustDemanglerParserTest {

	@Test
	public void testArrowOperator() {

		String demangled = "<std::Map<&str, for<'a> fn(&'a str) -> usize, std::Class>>::function";
		RustDemanglerParser parser = new RustDemanglerParser();
		DemangledObject dobj = parser.parse("mangled", demangled);

		String name = dobj.getName();
		assertEquals("function", name);

		Demangled ns = dobj.getNamespace();
		String nsName = ns.toString();
		assertEquals("<std::Map<&str,for<'a>fn(&'a_str)->usize,std::Class>>", nsName);
	}
}
