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
package ghidra.app.util.bin.format.pdb;

import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplyTables {

	private ApplyTables() {
		// static use only
	}

	static void applyTo(PdbParser pdbParser, XmlPullParser xmlParser, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		while (xmlParser.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}
			XmlElement elem = xmlParser.next();
			if (elem.isEnd() && elem.getName().equals("tables")) {
				break;
			}
			String tableName = elem.getAttribute("name");
			if ("Symbols".equals(tableName)) {
				ApplySymbols.applyTo(pdbParser, xmlParser, monitor, log);
			}
			else if ("SourceFiles".equals(tableName)) {
				ApplySourceFiles.applyTo(pdbParser, xmlParser, monitor, log);
			}
			else if ("Sections".equals(tableName)) {//TODO
			}
		}
	}

}
