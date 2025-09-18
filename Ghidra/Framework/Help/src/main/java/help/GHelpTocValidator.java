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
package help;

import static help.GHelpMsg.*;

import java.io.File;
import java.util.*;

import generic.application.GenericApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import help.validator.LinkDatabase;
import help.validator.location.HelpModuleCollection;

/**
 * Checks for errors in source TOC files, such as conflicting sort groups.  This validator is meant
 * to be used when all system TOC files have been built.  Individual module TOC files are validated
 * for correctness with their dependencies when they are built.  This class is needed to validate
 * all TOC files, including for leaf modules that don't have each other as dependencies.
 */
public class GHelpTocValidator {

	private static final String DEBUG_SWITCH = "-debug";

	private Collection<File> helpInputDirectories = new LinkedHashSet<>();

	public static void main(String[] args) throws Exception {
		GHelpTocValidator validator = new GHelpTocValidator();

		ApplicationConfiguration config = new ApplicationConfiguration();
		Application.initializeApplication(new GenericApplicationLayout("Help TOC Validator", "0.1"),
			config);

		validator.validate(args);
	}

	private void validate(String[] args) {

		parseArguments(args);

		List<File> allHelp = new ArrayList<>(helpInputDirectories);
		HelpModuleCollection help = HelpModuleCollection.fromFiles(allHelp);
		LinkDatabase linkDatabase = new LinkDatabase(help);
		linkDatabase.validateAllTOCs();
	}

	private void parseArguments(String[] args) {

		boolean debugEnabled = false;
		for (String opt : args) {
			if (opt.equals(DEBUG_SWITCH)) {
				debugEnabled = true;
			}
			else if (opt.startsWith("-")) {
				error("Unknown option " + opt);
				System.exit(1);
			}
			else {
				// It must just be an input
				helpInputDirectories.add(new File(opt));
			}
		}

		HelpBuildUtils.debug = debugEnabled;

		if (helpInputDirectories.size() == 0) {
			error("Must specify at least one help jar file");
			System.exit(1);
		}
	}
}
