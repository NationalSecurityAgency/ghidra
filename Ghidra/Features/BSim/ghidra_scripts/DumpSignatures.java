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
// Use the decompiler to generate signatures for the function currently containing the cursor
// and dump the signature hashes to the console
//@category BSim

import java.io.*;
import java.util.List;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.DebugSignature;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class DumpSignatures extends GhidraScript {

	private LSHVectorFactory vectorFactory;

	@Override
	public void run() throws Exception {
		Function func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			return;
		}
		buildLSHVectorFactory();
		boolean debug = false;
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.setSignatureSettings(vectorFactory.getSettings());
		decompiler.toggleSyntaxTree(false);
		if (!decompiler.openProgram(this.currentProgram)) {
			println("Unable to initalize the Decompiler interface");
			println(decompiler.getLastMessage());
			return;
		}
		if (!debug) {
			SignatureResult sigres = decompiler.generateSignatures(func, false, 10, null);
			StringBuffer buf = new StringBuffer("\n");
			for (int feature : sigres.features) {
				buf.append(Integer.toHexString(feature));
				buf.append("\n");
			}
			println(buf.toString());
		}
		else {
			Language language = this.currentProgram.getLanguage();
			List<DebugSignature> sigres = decompiler.debugSignatures(func, 10, null);
			StringBuffer buf = new StringBuffer("\n");
			for (int i = 0; i < sigres.size(); ++i) {
				sigres.get(i).printRaw(language, buf);
				buf.append("\n");
			}
			println(buf.toString());
		}
		decompiler.closeProgram();
		decompiler.dispose();
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

}
