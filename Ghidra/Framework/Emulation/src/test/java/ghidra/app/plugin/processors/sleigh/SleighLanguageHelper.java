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

import java.io.IOException;
import java.util.*;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.program.model.lang.*;
import resources.ResourceManager;

public class SleighLanguageHelper {
	public static SleighLanguage getMockBE64Language()
			throws UnknownInstructionException, SAXException, IOException {

		ResourceFile cSpecFile =
			new ResourceFile(ResourceManager.getResource("mock.cspec").getPath());
		CompilerSpecDescription cSpecDesc =
			new SleighCompilerSpecDescription(new CompilerSpecID("default"), "default", cSpecFile);

		ResourceFile lDefsFile =
			new ResourceFile(ResourceManager.getResource("mock.ldefs").getPath());
		ResourceFile pSpecFile =
			new ResourceFile(ResourceManager.getResource("mock.pspec").getPath());
		ResourceFile slaFile =
			new ResourceFile(ResourceManager.getResource("mock.sla").getPath());
		SleighLanguageDescription langDesc = new SleighLanguageDescription(
			new LanguageID("Mock:BE:64:default"),
			"Mock language (64-bit BE)",
			Processor.findOrPossiblyCreateProcessor("Mock"),
			Endian.BIG, // endian
			Endian.BIG, // instructionEndian
			64,
			"default", // variant
			0, // major version
			0, // minor version
			false, // deprecated
			new HashMap<>(), // truncatedSpaceMap
			new ArrayList<>(List.of(cSpecDesc)),
			new HashMap<>() // externalNames
		);
		langDesc.setDefsFile(lDefsFile);
		langDesc.setSpecFile(pSpecFile);
		langDesc.setSlaFile(slaFile);

		return new SleighLanguage(langDesc);
	}
}
