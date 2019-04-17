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
package ghidra.app.analyzers;

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

public class Patterns {

	private static final String PATTERN_FILE_NAME = "patternfile";
	private static final String DATA_PATTERNS = "data/patterns";

	public static ProgramDecisionTree getPatternDecisionTree() {
		List<ResourceFile> patternDirs = Application.findModuleSubDirectories(DATA_PATTERNS);
		List<ResourceFile> patternConstraintFiles = findPatternConstraintFiles(patternDirs);
		ProgramDecisionTree decisionTree = new ProgramDecisionTree();
		decisionTree.registerPropertyName(PATTERN_FILE_NAME);
		for (ResourceFile resourceFile : patternConstraintFiles) {
			try {
				decisionTree.loadConstraints(resourceFile);
			}
			catch (Exception e) {
				Msg.showError(Patterns.class, null, "Error Processing Pattern File",
					"Error processing pattern file " + resourceFile + "\n" + e.getMessage());
			}
		}
		return decisionTree;
	}

	public static boolean hasPatternFiles(Program program, ProgramDecisionTree decisionTree) {
		DecisionSet decisionsSet = decisionTree.getDecisionsSet(program, PATTERN_FILE_NAME);
		return !decisionsSet.isEmpty();
	}

	/**
	 * Find any pattern files associated with this program
	 * @param program find pattern files associated with this program
	 * @return the array of File objects, one for each file
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws SAXException 
	 * @throws XmlParseException 
	 */
	public static ResourceFile[] findPatternFiles(Program program, ProgramDecisionTree decisionTree)
			throws FileNotFoundException, IOException, XmlParseException {

		DecisionSet decisionsSet = decisionTree.getDecisionsSet(program, PATTERN_FILE_NAME);
		List<String> values = decisionsSet.getValues();

		List<ResourceFile> patternFileList = new ArrayList<ResourceFile>();
		List<ResourceFile> patternDirs = Application.findModuleSubDirectories(DATA_PATTERNS);

		for (String patternFileName : values) {
			patternFileList.add(getPatternFile(patternDirs, patternFileName));
		}

		return patternFileList.toArray(new ResourceFile[patternFileList.size()]);
	}

	private static ResourceFile getPatternFile(List<ResourceFile> patternDirs,
			String patternFileName) throws FileNotFoundException {
		for (ResourceFile dir : patternDirs) {
			ResourceFile file = new ResourceFile(dir, patternFileName);
			if (file.exists()) {
				return file;
			}
		}
		throw new FileNotFoundException("can't find pattern file: " + patternFileName);
	}

	private static List<ResourceFile> findPatternConstraintFiles(List<ResourceFile> patternDirs) {

		List<ResourceFile> patternConstraintFiles = new ArrayList<ResourceFile>();

		for (ResourceFile dir : patternDirs) {
			ResourceFile file = new ResourceFile(dir, "patternconstraints.xml");
			if (file.exists()) {
				patternConstraintFiles.add(file);
			}
		}
		return patternConstraintFiles;
	}
}
