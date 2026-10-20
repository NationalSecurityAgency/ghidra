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
//Decompile the current program's functions, then output facts files corresponding to the pcodes
//@category PCode

import java.io.File;

import ghidra.app.plugin.core.decompiler.export.ExportDecompilationTask;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskLauncher;

public class ExportPcodeViaDecoderScript extends GhidraScript {

	File outputDirectory;

	@Override
	protected void run() throws Exception {

		String[] args = getScriptArgs();
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		if (args.length >= 1) {
			outputDirectory = new File(args[0]);
		}
		else {
			outputDirectory = askDirectory("Select Directory for Results", "OK");
		}

		long startTime = System.nanoTime();

		ExportDecompilationTask task =
			new ExportDecompilationTask("Export Pcode", currentProgram, outputDirectory);
		TaskLauncher.launch(task);

		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000;
		println("total duration: " + Long.toString(duration));
	}

}
