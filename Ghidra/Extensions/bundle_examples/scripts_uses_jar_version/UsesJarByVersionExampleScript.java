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
// Example use of jar bundle with a version constraint
//@category Examples.Bundle
//@importpackage org.jarlib;version="[2,3)"

import org.jarlib.JarUtil;

import ghidra.app.script.GhidraScript;

public class UsesJarByVersionExampleScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		println("This script shows the use of " + JarUtil.class.getCanonicalName() + ".");
		println("  a class defined in an external jar bundle.");
		println("There are two versions of the jar in the bundle examples directory,");
		println(" since \"@importpackage\" declaration doesn't specify a version, either");
		println(" of the jar bundles, scripts_jar1.jar or scripts_jar2.jar works.");
		println(" Try enabling only one of the \"scripts_jar*\" bundles and rerun this script.");

		println("Currently using JarUtil version " + JarUtil.getVersion());
	}
}
