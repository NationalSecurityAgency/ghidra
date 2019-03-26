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
package ghidra.app.plugin.core.analysis;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.xml.sax.SAXException;

import generic.constraint.DecisionSet;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.constraint.ProgramDecisionTree;
import ghidra.xml.XmlParseException;

class NonReturningFunctionNames {

	private static final String CONSTRAINED_FILENAME_PROPERTY = "functionNamesFile";
	private static final String DATA_DIR = "data";

	private static ProgramDecisionTree decisionTree;

	private NonReturningFunctionNames() {
	}

	static synchronized ProgramDecisionTree getDecisionTree() {
		if (decisionTree != null) {
			return decisionTree;
		}
		List<ResourceFile> dataDirs = Application.findModuleSubDirectories(DATA_DIR);
		List<ResourceFile> fileList = findDataFiles(dataDirs);
		decisionTree = new ProgramDecisionTree();
		decisionTree.registerPropertyName(CONSTRAINED_FILENAME_PROPERTY);
		for (ResourceFile resourceFile : fileList) {
			try {
				decisionTree.loadConstraints(resourceFile);
			}
			catch (Exception e) {
				Msg.showError(NonReturningFunctionNames.class, null,
					"Error Processing Pattern File", "Error processing pattern file " +
						resourceFile + "\n" + e.getMessage());
			}
		}
		return decisionTree;
	}

	static boolean hasDataFiles(Program program) {
		DecisionSet decisionsSet =
			getDecisionTree().getDecisionsSet(program, CONSTRAINED_FILENAME_PROPERTY);
		return !decisionsSet.isEmpty();
	}

	/**
	 * Find any data files associated with this program
	 * @param program find data files associated with this program
	 * @return the array of File objects, one for each file
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws SAXException 
	 * @throws XmlParseException 
	 */
	static ResourceFile[] findDataFiles(Program program) throws FileNotFoundException, IOException,
			XmlParseException {

		DecisionSet decisionsSet =
			getDecisionTree().getDecisionsSet(program, CONSTRAINED_FILENAME_PROPERTY);
		List<String> values = decisionsSet.getValues();

		List<ResourceFile> fileList = new ArrayList<ResourceFile>();
		List<ResourceFile> dataDirs = Application.findModuleSubDirectories(DATA_DIR);

		for (String patternFileName : values) {
			fileList.add(getDataFile(dataDirs, patternFileName));
		}

		return fileList.toArray(new ResourceFile[fileList.size()]);
	}

	private static ResourceFile getDataFile(List<ResourceFile> dataDirs, String fileName)
			throws FileNotFoundException {
		for (ResourceFile dir : dataDirs) {
			ResourceFile file = new ResourceFile(dir, fileName);
			if (file.exists()) {
				return file;
			}
		}
		throw new FileNotFoundException("can't find data file: " + fileName);
	}

	private static List<ResourceFile> findDataFiles(List<ResourceFile> patternDirs) {

		List<ResourceFile> patternConstraintFiles = new ArrayList<ResourceFile>();

		for (ResourceFile dir : patternDirs) {
			ResourceFile file = new ResourceFile(dir, "noReturnFunctionConstraints.xml");
			if (file.exists()) {
				patternConstraintFiles.add(file);
			}
		}
		return patternConstraintFiles;
	}
}
