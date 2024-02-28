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
package ghidra.app.plugin.processors.sleigh;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.antlr.runtime.RecognitionException;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.pcodeCPort.slgh_compile.SleighCompileLauncher;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.DecoderException;
import ghidra.util.Msg;
import resources.ResourceManager;

public class SleighLanguageHelper {
	private static ResourceFile getResourceFile(String name) {
		URL url = ResourceManager.getResource(name);
		if (url == null) {
			return null;
		}
		return new ResourceFile(url.getPath());
	}

	public static SleighLanguage getMockBE64Language()
			throws DecoderException, UnknownInstructionException, SAXException, IOException {

		ResourceFile cSpecFile = getResourceFile("mock.cpsec");
		CompilerSpecDescription cSpecDesc =
			new SleighCompilerSpecDescription(new CompilerSpecID("default"), "default", cSpecFile);
		ResourceFile lDefsFile = getResourceFile("mock.ldefs");
		ResourceFile pSpecFile = getResourceFile("mock.pspec");
		ResourceFile slaSpecFile = getResourceFile("mock.slaspec");
		ResourceFile slaFile = getResourceFile("mock.sla");
		if (slaFile == null || !slaFile.exists() ||
			(slaSpecFile.lastModified() > slaFile.lastModified())) {
			assertNotNull("Cannot find mock.slaspec", slaSpecFile);
			Msg.debug(SleighLanguageHelper.class, "Compiling mock.slaspec");
			try {
				assertEquals("Failed to compile mock.slaspec", 0,
					SleighCompileLauncher.runMain(new String[] { slaSpecFile.getAbsolutePath() }));
			}
			catch (IOException | RecognitionException e) {
				throw new AssertionError(e);
			}
			slaFile = getResourceFile("mock.sla");
			assertNotNull("Cannot find mock.sla (after compilation)");
		}

		SleighLanguageDescription langDesc = new SleighLanguageDescription(
			new LanguageID("Mock:BE:64:default"), "Mock language (64-bit BE)",
			Processor.findOrPossiblyCreateProcessor("Mock"), Endian.BIG, // endian
			Endian.BIG, // instructionEndian
			64, "default", // variant
			0, // major version
			0, // minor version
			false, // deprecated
			new HashMap<>(), // truncatedSpaceMap
			new ArrayList<>(List.of(cSpecDesc)), new HashMap<>() // externalNames
		);
		langDesc.setDefsFile(lDefsFile);
		langDesc.setSpecFile(pSpecFile);
		langDesc.setSlaFile(slaFile);

		return new SleighLanguage(langDesc);
	}
}
