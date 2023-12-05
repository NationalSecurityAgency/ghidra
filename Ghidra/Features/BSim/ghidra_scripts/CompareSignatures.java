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
// Use the decompiler to generate a signature for the current function containing the cursor
// If we remember the last signature that was generated, compare this signature with
// the last signature and print the similarity
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

public class CompareSignatures extends GhidraScript {

	private LSHVectorFactory vectorFactory;

	private LSHVector generateVector(Function f, Program program) {
		DecompInterface decompiler = new DecompInterface();
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

	private static void readWeights(LSHVectorFactory vectorFactory, ResourceFile weightsFile)
			throws FileNotFoundException, IOException, SAXException {
		InputStream input = weightsFile.getInputStream();
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(input, "Vector weights parser",
			SpecXmlUtils.getXmlHandler(), false);
		vectorFactory.readWeights(parser);
		input.close();
	}

	private void buildLSHVectorFactory() {
		vectorFactory = new WeightedLSHCosineVectorFactory();
		try {
			LanguageID id = currentProgram.getLanguageID();
			ResourceFile defaultWeightsFile = GenSignatures.getWeightsFile(id, id);
			readWeights(vectorFactory, defaultWeightsFile);
		}
		catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected void run() throws Exception {
		Function func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			return;
		}
		buildLSHVectorFactory();
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
