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
// Inter-bundle dependency example.
//@category Examples.Bundle
//@importpackage org.other.lib

import org.other.lib.Util; // from another bundle, use @importpackage

import ghidra.app.script.GhidraScript;

public class InterBundleExampleScript extends GhidraScript {
	@Override
	public void run() throws Exception {
		println("This script shows the use of " + Util.class.getCanonicalName() +
			" from a different bundle.");
		println(
			"In this case, the dependency is declared with the metadata comment \"//@importpackage org.other.lib\"");

		Util.doStuff(this);
	}
}
