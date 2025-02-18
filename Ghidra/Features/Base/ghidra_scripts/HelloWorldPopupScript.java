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
//Writes "Hello World" in a popup dialog.
//@__params_start
//@category Examples
//@toolbar world.png
//@menupath Tools.Scripts Manager.Hello World Popup Script
//@__params_end

import ghidra.app.script.GhidraScript;

public class HelloWorldPopupScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		popup("Hello World");
	}
}
