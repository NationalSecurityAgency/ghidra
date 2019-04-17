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
package ghidra.file.jad;

import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.io.File;

class JarDecompilerTask extends Task {
	private File file;
	private String desc;

	JarDecompilerTask(File file, String desc) {
		super("Decompiling...", true, true, false);
		this.file = file;
		this.desc = desc;
	}

	@Override
	public void run(TaskMonitor monitor) {

		monitor.setMessage(file.getAbsolutePath());
		monitor.setIndeterminate(true);

		try {
			JadProcessWrapper wrapper = new JadProcessWrapper(file);

			JadProcessController controller = new JadProcessController(wrapper, desc);
			controller.decompile(45, monitor);
		}
		catch (Exception e) {
			Msg.info(this, "Exception in JarDecompileTask", e);
		}
	}

}
