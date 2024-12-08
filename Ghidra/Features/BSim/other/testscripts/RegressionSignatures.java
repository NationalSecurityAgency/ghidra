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
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.description.DescriptionManager;

/**
 * This script is used by the unit test BSimServerTest
 */
public class RegressionSignatures extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String md5string = currentProgram.getExecutableMD5();
		if ((md5string == null) || (md5string.length() < 10))
			throw new IOException("Could not get MD5 on file: " + currentProgram.getName());
		String basename = "sigs_" + md5string;
		File file = null;
		// This form of askString will work for both standalone execution or for parallel
		File workingdir = askDirectory("RegressionSignatures:", "Working directory");
		file = new File(workingdir, basename);

		LSHVectorFactory vectorFactory = FunctionDatabase.generateLSHVectorFactory();
		Configuration config = FunctionDatabase.loadConfigurationTemplate("medium_64");
		vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		GenSignatures gensig = new GenSignatures(true);
		gensig.setVectorFactory(vectorFactory);

		List<String> names = new ArrayList<String>();
		names.add("Test Category");
		gensig.addExecutableCategories(names);
		String repo = "ghidra://localhost/repo";
		String path = "/raw";
		gensig.openProgram(this.currentProgram, null, null, null, repo, path);
		FunctionManager fman = currentProgram.getFunctionManager();
		Iterator<Function> iter = fman.getFunctions(true);
		gensig.scanFunctions(iter, fman.getFunctionCount(), monitor);
		FileWriter fwrite = new FileWriter(file);
		DescriptionManager manager = gensig.getDescriptionManager();
		manager.saveXml(fwrite);
		fwrite.close();
	}

}
