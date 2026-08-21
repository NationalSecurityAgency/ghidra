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
package ghidra.app.plugin.core.debug.taint;

import java.io.IOException;

import ghidra.app.plugin.core.debug.taint.EmulatorTaintState.KTV;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.*;

public class SarifKeyValueWriter extends AbstractExtWriter {

	private ExtKeyValue isf;
	private WrappedLogicalLocation wll;

	public SarifKeyValueWriter(KTV ktv, WrappedLogicalLocation wll)
			throws IOException {
		super(null);
		this.isf = new ExtKeyValue(ktv);
		this.wll = wll;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genData(monitor);
		root.add("structuredObject", objects);
	}

	private void genData(TaskMonitor monitor) {
		ExtLogicalLocation lloc = wll.getLogicalLocation();
		SarifObject sarif = new SarifObject(lloc.getDecoratedName(), "VALUE", lloc, getTree(isf),
			wll.getAddress(), wll.getIndex());
		objects.add(getTree(sarif));
	}

}
