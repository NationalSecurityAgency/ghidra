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
package sarif.export;

import java.io.IOException;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import ghidra.program.model.data.ISF.AbstractIsfWriter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class SarifWriterTask extends Task {

	protected AbstractIsfWriter writer;
	protected JsonArray results;

	public SarifWriterTask(String tag, AbstractIsfWriter writer, JsonArray results) {
		super(tag, true, false, true);
		this.writer = writer;
		this.results = results;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			try {
				writer.getRootObject(monitor);
				JsonArray res = writer.getResults();
				for (JsonElement element : res) {
					if (monitor.isCancelled()) {
						break;
					}
					results.add(element);
				}
			} finally {
				writer.close();
			}
		} catch (CancelledException e) {
			// user cancelled; ignore
		} catch (IOException e) {
			Msg.error("Export Data Types Failed", "Error exporting Data Types: " + e);
			return;
		}
	}
}
