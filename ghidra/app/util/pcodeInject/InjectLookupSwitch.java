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
package ghidra.app.util.pcodeInject;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;

public class InjectLookupSwitch extends InjectPayloadJava {

	public InjectLookupSwitch(String sourceName, SleighLanguage language) {
		super(sourceName, language);
	}

	@Override
	public String getPcodeText(Program program, String context) {
		InjectContext injectContext = getInjectContext(program, context);
		String pcodeText = null;
		try {
			pcodeText = SwitchMethods.getPcodeForLookupSwitch(injectContext, program);
		} catch (IOException e) {
			e.printStackTrace();
			pcodeText = "SP = SP;\n";
		}
		return pcodeText;
	}

}
