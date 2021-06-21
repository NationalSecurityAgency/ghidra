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
//An example of building a single minimal Ghidra jar file.
//@category Examples

import java.io.File;
import java.util.List;

import generic.jar.ApplicationModule;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.util.GhidraJarBuilder;

// This script creates a minimal jar file with most gui modules and help files removed.
// To create a complete Ghidra jar file, add all modules and remove the excluded file extensions.

public class BuildGhidraJarScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		GhidraJarBuilder builder = new GhidraJarBuilder(Application.getApplicationLayout());

		builder.setMainClass("ghidra.JarRun");  // default is ghidra.JarRun, only here if you want 
		// to change it to something else.

		// by default,  all framework and processor modules are include, but no extensions
		// modules are included unless their Module.manifest file states that it
		// should be excluded by default

//		// lets just include x86 and arm
//		builder.removeAllProcessorModules();
//		builder.addModule("x86");

		// if you want all modules, uncomment the following line
		//builder.addAllModules();

		List<ApplicationModule> moduleList = builder.getIncludedModules();
		for (ApplicationModule module : moduleList) {
			println("Include " + module.getName());
		}
		moduleList = builder.getExcludedModules();
		for (ApplicationModule module : moduleList) {
			println("Exclude " + module.getName());
		}

		// don't include help or processor manuals
		builder.addExcludedFileExtension(".htm");
		builder.addExcludedFileExtension(".html");
		builder.addExcludedFileExtension(".pdf");

		File installDir = Application.getInstallationDirectory().getFile(true);
		builder.buildJar(new File(installDir, "ghidra.jar"), null, monitor);

		// uncomment the following line to create a src zip for debugging.
		// builder.buildSrcZip(new File(installDir, "GhidraSrc.zip"), monitor);
	}
}
