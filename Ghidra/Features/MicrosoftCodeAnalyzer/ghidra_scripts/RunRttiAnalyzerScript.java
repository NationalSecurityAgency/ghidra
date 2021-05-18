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
// Script to fix up Windows RTTI vtables and structures 
//@category C++

import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;

public class RunRttiAnalyzerScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		runRTTIAnalyzer();
	}

	private void runRTTIAnalyzer() throws Exception {
		Analyzer analyzer = new RttiAnalyzer();
		analyzer.added(currentProgram, currentProgram.getAddressFactory().getAddressSet(), monitor,
			new MessageLog());
	}
}
