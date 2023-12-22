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
// This script will print information about a BSim comparison of two functions. Navigate to the
// first function, run this script, navigate to the second function, and run the script again.
// The two functions can be in different (open) programs.  Subsequent runs of the script will
// compare the current function and the previous function.  For each comparison, the user selects
// which weights file to use.
//@category BSim

import java.io.IOException;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.Application;
import ghidra.util.exception.CancelledException;
import utilities.util.reflection.ReflectionUtilities;

public class CompareBSimSignaturesSpecifyWeightsScript extends CompareBSimSignaturesScript {

	private static final String[] WEIGHT_FILES = { "lshweights_nosize.xml", "lshweights_32.xml",
		"lshweights_64.xml", "lshweights_cpool.xml" };

	@Override
	protected boolean buildLSHVectorFactory() {
		vectorFactory = new WeightedLSHCosineVectorFactory();
		GhidraValuesMap values = new GhidraValuesMap();
		values.defineChoice("weights file", WEIGHT_FILES[0], WEIGHT_FILES);
		try {
			askValues("Select Weights File", "Select Weights File", values);
		}
		catch (CancelledException e) {
			return false;
		}
		String weightsFile = values.getChoice("weights file");
		ResourceFile defaultWeightsFile = Application.findDataFileInAnyModule(weightsFile);
		try {
			readWeights(vectorFactory, defaultWeightsFile);
		}
		catch (IOException | SAXException e) {
			printerr("Unexpected Exception...");
			printerr(ReflectionUtilities.stackTraceToString(e));
			return false;
		}
		return true;

	}
}
