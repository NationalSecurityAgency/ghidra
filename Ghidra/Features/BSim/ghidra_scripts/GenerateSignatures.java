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
// Generate signatures for every function in the current executable and write in XML form to
// a user specified file.
//@category BSim

import java.io.*;
import java.util.Iterator;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class GenerateSignatures extends GhidraScript {

	@Override
	public void run() throws Exception {
		final String md5string = currentProgram.getExecutableMD5();
		if ((md5string == null) || (md5string.length() < 10)) {
			throw new IOException("Could not get MD5 on file: " + currentProgram.getName());
		}
		final String basename = "sigs_" + md5string;
		System.setProperty("ghidra.output", basename); // Inform parallel controller of output name
		File file = null;
		// This form of askString will work for both standalone execution or for parallel
		final File workingdir = askDirectory("GenerateSignatures:", "Working directory");
		if (!workingdir.isDirectory()) {
			popup("Must select a working directory!");
			return;
		}
		file = new File(workingdir, basename);

		final LSHVectorFactory vectorFactory = FunctionDatabase.generateLSHVectorFactory();
		final GenSignatures gensig = new GenSignatures(true);
		try {
			final String templatename =
				askString("GenerateSignatures:", "Database template", "medium_nosize");
			final Configuration config = FunctionDatabase.loadConfigurationTemplate(templatename);
			vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
			gensig.setVectorFactory(vectorFactory);
			gensig.addExecutableCategories(config.info.execats);
			gensig.addFunctionTags(config.info.functionTags);
			gensig.addDateColumnName(config.info.dateColumnName);
			final String repo = "ghidra://localhost/" + state.getProject().getName();
			final String path = GenSignatures.getPathFromDomainFile(currentProgram);
			gensig.openProgram(this.currentProgram, null, null, null, repo, path);
			final FunctionManager fman = currentProgram.getFunctionManager();
			final Iterator<Function> iter = fman.getFunctions(true);
			gensig.scanFunctions(iter, fman.getFunctionCount(), monitor);
			try (FileWriter fwrite = new FileWriter(file)) {
				final DescriptionManager manager = gensig.getDescriptionManager();
				manager.saveXml(fwrite);
				fwrite.close();
			}
		}
		finally {
			gensig.dispose();
		}

	}

}
