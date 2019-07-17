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
//Ask for an integer and print the current 
//program?s name that many times to the console
//@category GADC

import ghidra.app.script.GhidraScript;

public class Lab4Script extends GhidraScript {
	@Override
	public void run() throws Exception {
		int n = askInt("How Many Times?", "N");
		for (int i = 0; i < n; ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			println(i + ". " + currentProgram.getName());
			Thread.sleep(1000);
		}
	}
}
