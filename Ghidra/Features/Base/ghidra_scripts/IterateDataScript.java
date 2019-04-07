/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//Iterates over all defined data in the current program.
//@category Iteration

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;

public class IterateDataScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		Data data = getFirstData();

		while (true) {

			if (monitor.isCancelled()) {
				break;
			}

			if (data == null) {
				break;
			}

			StringBuffer buffer = new StringBuffer();

			buffer.append(data.getMinAddress());
			buffer.append(' ');
			buffer.append(data.getMnemonicString());
			buffer.append(' ');
			buffer.append(data.getValue());

			println(buffer.toString());

			data = getDataAfter(data);
		}
	}

}
