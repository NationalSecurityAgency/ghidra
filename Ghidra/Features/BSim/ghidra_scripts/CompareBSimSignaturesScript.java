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
// compare the current function and the previous function.  For each comparison, the BSim signature
// weights file is chosen based on the architecture of the current function.
//@category BSim

import java.io.*;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.lsh.vector.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;
import utilities.util.reflection.ReflectionUtilities;

public class CompareBSimSignaturesScript extends GhidraScript {

	protected LSHVectorFactory vectorFactory;

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("This script must be run from the Ghidra GUI");
			return;
		}
		if (currentProgram == null) {
			popup("This script requires an open program");
			return;
		}
		Function func = getFunctionContaining(currentAddress);
		if (func == null) {
			popup("currentAddress must be in a function for this script.");
			return;
		}
		ProgramManager programManager = state.getTool().getService(ProgramManager.class);
		String lastProgramIdString = System.getProperty("ghidra.lastprogram");
		if (lastProgramIdString == null) {
			setProperties(func);
			return;
		}
		Program lastProgram =
			getProgram(programManager.getAllOpenPrograms(), Long.parseLong(lastProgramIdString));
		if (lastProgram == null) {
			setProperties(func);
			return;
		}
		String addrstring = System.getProperty("ghidra.lastaddress");
		if (addrstring == null) {
			setProperties(func);
			return;
		}
		Address addr = lastProgram.getAddressFactory().getAddress(addrstring);
		Function lastfunction = lastProgram.getFunctionManager().getFunctionAt(addr);
		if (lastfunction == null) {
			setProperties(func);
			return;
		}
		if (!buildLSHVectorFactory()) {
			return;
		}
		LSHVector vec = generateVector(func, currentProgram);
		LSHVector lastvector = generateVector(lastfunction, lastProgram);
		VectorCompare veccompare = new VectorCompare();
		double sim = lastvector.compare(vec, veccompare);
		double signif = vectorFactory.calculateSignificance(veccompare);
		StringBuilder buf = new StringBuilder();
		buf.append("Comparison results:\n");
		buf.append(lastProgram.getName());
		buf.append(".");
		buf.append(lastfunction.getName());
		buf.append(" vs. ");
		buf.append(currentProgram.getName());
		buf.append(".");
		buf.append(func.getName());
		buf.append("\n  Similarity: ");
		buf.append(Double.toString(sim));
		buf.append("\n  Significance: ");
		buf.append(Double.toString(signif));
		buf.append("\n");
		lastvector.compareDetail(vec, buf);
		println(buf.toString());
	}

	private void setProperties(Function func) {
		System.setProperty("ghidra.lastprogram",
			Long.toString(currentProgram.getUniqueProgramID()));
		String addrstring = func.getEntryPoint().toString();
		System.setProperty("ghidra.lastaddress", addrstring);
	}

	private LSHVector generateVector(Function f, Program program) {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.setOptions(new DecompileOptions());
			decompiler.toggleSyntaxTree(false);
			decompiler.setSignatureSettings(vectorFactory.getSettings());
			if (!decompiler.openProgram(program)) {
				println("Unable to initalize the Decompiler interface");
				println(decompiler.getLastMessage());
				return null;
			}
			SignatureResult sigres = decompiler.generateSignatures(f, false, 10, null);
			LSHVector vec = vectorFactory.buildVector(sigres.features);
			return vec;
		}
		finally {
			decompiler.closeProgram();
			decompiler.dispose();
		}
	}

	private Program getProgram(Program[] progarray, long id) {
		if (progarray == null) {
			return null;
		}
		for (Program prog : progarray) {
			if (prog.getUniqueProgramID() == id) {
				return prog;
			}
		}
		return null;
	}

	protected static void readWeights(LSHVectorFactory vectorFactory, ResourceFile weightsFile)
			throws FileNotFoundException, IOException, SAXException {
		InputStream input = weightsFile.getInputStream();
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(input, "Vector weights parser",
			SpecXmlUtils.getXmlHandler(), false);
		vectorFactory.readWeights(parser);
		input.close();
	}

	protected boolean buildLSHVectorFactory() {
		vectorFactory = new WeightedLSHCosineVectorFactory();
		try {
			LanguageID id = currentProgram.getLanguageID();
			ResourceFile defaultWeightsFile = GenSignatures.getWeightsFile(id, id);
			readWeights(vectorFactory, defaultWeightsFile);
		}
		catch (IOException | SAXException e) {
			printerr("Unexpected Exception...");
			printerr(ReflectionUtilities.stackTraceToString(e));
		}
		return true;
	}
}
