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
// Compare the BSim feature vectors of two functions.
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
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class CompareSignaturesSpecifyWeights extends GhidraScript {

	private static final String DEFAULT_LSH_WEIGHTS_FILE = "lshweights_nosize.xml";
	private LSHVectorFactory vectorFactory;

	private LSHVector generateVector(Function f, Program program) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.setSignatureSettings(vectorFactory.getSettings());
		decompiler.toggleSyntaxTree(false);
		if (!decompiler.openProgram(program)) {
			println("Unable to initalize the Decompiler interface");
			println(decompiler.getLastMessage());
			return null;
		}

		SignatureResult sigres = decompiler.generateSignatures(f, false, 10, null);

		LSHVector vec = vectorFactory.buildVector(sigres.features);
		return vec;
	}

	private static void readWeights(LSHVectorFactory vectorFactory, ResourceFile weightsFile)
			throws FileNotFoundException, IOException, SAXException {
		InputStream input = weightsFile.getInputStream();
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(input, "Vector weights parser",
			SpecXmlUtils.getXmlHandler(), false);
		vectorFactory.readWeights(parser);
		input.close();
	}

	private boolean buildLSHVectorFactory() {
		vectorFactory = new WeightedLSHCosineVectorFactory();
		try {
			String weightsFile =
				askString("Enter weights file name", "weights file", DEFAULT_LSH_WEIGHTS_FILE);
			ResourceFile defaultWeightsFile = Application.findDataFileInAnyModule(weightsFile);
			readWeights(vectorFactory, defaultWeightsFile);
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		catch (SAXException e) {
			e.printStackTrace();
			return false;
		}
		catch (CancelledException e) {
			return false;
		}
		return true;
	}

	private Program getProgram(Program[] progarray, String name) {
		if ((name == null) || (progarray == null)) {
			return null;
		}
		for (Program prog : progarray) {
			if (name.equals(prog.getName())) {
				return prog;
			}
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		Function func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			return;
		}
		if (!buildLSHVectorFactory()) {
			return;
		}
		LSHVector vec = generateVector(func, currentProgram);
		ProgramManager programManager = state.getTool().getService(ProgramManager.class);
		Program[] progarray = programManager.getAllOpenPrograms();
		String lastprogram_string = System.getProperty("ghidra.lastprogram");
		Program lastprogram = getProgram(progarray, lastprogram_string);
		VectorCompare veccompare = new VectorCompare();
		if (lastprogram != null) {
			String addrstring = System.getProperty("ghidra.lastaddress");
			if (addrstring != null) {
				Address addr = lastprogram.getAddressFactory().getAddress(addrstring);
				Function lastfunction = lastprogram.getFunctionManager().getFunctionAt(addr);
				if (lastfunction != null) {
					LSHVector lastvector = generateVector(lastfunction, lastprogram);
					double sim = lastvector.compare(vec, veccompare);
					double signif = vectorFactory.calculateSignificance(veccompare);
					StringBuilder buf = new StringBuilder();
					buf.append("Comparison results:\n");
					buf.append(lastprogram.getName());
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
			}
		}
		System.setProperty("ghidra.lastprogram", currentProgram.getName());
		String addrstring = func.getEntryPoint().toString();
		System.setProperty("ghidra.lastaddress", addrstring);
	}
}
