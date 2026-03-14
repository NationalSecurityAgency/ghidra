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
package ghidra.electron.headless;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

interface HeadlessExecutionEngine {
	ExecutionOutcome run(ProjectRecord project, JobRecord job, Path jobDir, ImportAnalyzeRequest request,
			ExecutionListener listener) throws Exception;

	void cancel(JobRecord job);
}

interface ExecutionListener {
	void onProgress(String phase, String message, Integer percent);

	void onLog(String stream, String message);
}

class ExecutionOutcome {
	final int exitCode;
	final boolean cancelled;

	ExecutionOutcome(int exitCode, boolean cancelled) {
		this.exitCode = exitCode;
		this.cancelled = cancelled;
	}
}

class ScriptProcessExecutionEngine implements HeadlessExecutionEngine {
	private final Path repoRoot;
	private volatile Process currentProcess;

	ScriptProcessExecutionEngine(Path repoRoot) {
		this.repoRoot = repoRoot;
	}

	@Override
	public synchronized void cancel(JobRecord job) {
		job.cancelRequested = true;
		if (currentProcess != null) {
			currentProcess.destroy();
		}
	}

	@Override
	public ExecutionOutcome run(ProjectRecord project, JobRecord job, Path jobDir,
			ImportAnalyzeRequest request, ExecutionListener listener) throws Exception {
		Path appLog = jobDir.resolve("artifacts").resolve("application.log");
		Path scriptLog = jobDir.resolve("artifacts").resolve("script.log");
		Path processLog = jobDir.resolve("artifacts").resolve("process-output.log");
		Files.createDirectories(appLog.getParent());
		Files.writeString(processLog, "", StandardCharsets.UTF_8, StandardOpenOption.CREATE,
			StandardOpenOption.TRUNCATE_EXISTING);

		List<String> command = buildCommand(project, request, appLog, scriptLog);
		ProcessBuilder pb = new ProcessBuilder(command);
		pb.directory(repoRoot.toFile());
		listener.onProgress("setup", "Launching Ghidra headless process", 5);
		Process process = pb.start();
		synchronized (this) {
			currentProcess = process;
		}

		Thread stdoutThread = streamThread(process.getInputStream(), "stdout", processLog, listener);
		Thread stderrThread = streamThread(process.getErrorStream(), "stderr", processLog, listener);
		stdoutThread.start();
		stderrThread.start();

		listener.onProgress("import", "Headless process started", 20);
		int exitCode = process.waitFor();
		stdoutThread.join();
		stderrThread.join();
		synchronized (this) {
			currentProcess = null;
		}
		boolean cancelled = job.cancelRequested && exitCode != 0;
		listener.onProgress(cancelled ? "finalize" : "analysis",
			cancelled ? "Cancellation observed" : "Headless process exited", cancelled ? 100 : 90);
		return new ExecutionOutcome(exitCode, cancelled);
	}

	private Thread streamThread(InputStream stream, String streamName, Path processLog,
			ExecutionListener listener) {
		return new Thread(() -> {
			try (BufferedReader reader =
				new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
				String line;
				while ((line = reader.readLine()) != null) {
					Files.writeString(processLog, line + System.lineSeparator(), StandardCharsets.UTF_8,
						StandardOpenOption.CREATE, StandardOpenOption.APPEND);
					listener.onLog(streamName, line);
					if (line.toLowerCase(Locale.ROOT).contains("analy")) {
						listener.onProgress("analysis", line, 60);
					}
				}
			}
			catch (IOException e) {
				listener.onLog("system", "Failed to read " + streamName + ": " + e.getMessage());
			}
		}, "headless-" + streamName + "-reader");
	}

	private List<String> buildCommand(ProjectRecord project, ImportAnalyzeRequest request, Path appLog,
			Path scriptLog) {
		Path projectPath = Paths.get(project.projectPath);
		String projectDir = Optional.ofNullable(projectPath.getParent()).orElse(projectPath).toString();
		String projectName = projectPath.getFileName().toString();
		Path analyzeHeadless = repoRoot.resolve("Ghidra/RuntimeScripts/Linux/support/analyzeHeadless");

		List<String> command = new ArrayList<>();
		command.add("bash");
		command.add(analyzeHeadless.toString());
		command.add(projectDir);
		command.add(projectName);
		command.add("-import");
		command.add(request.inputPath);
		command.add("-log");
		command.add(appLog.toString());
		command.add("-scriptlog");
		command.add(scriptLog.toString());

		if (Boolean.TRUE.equals(request.recursive)) {
			command.add("-recursive");
		}
		if (Boolean.TRUE.equals(request.readOnly)) {
			command.add("-readOnly");
		}
		if (Boolean.TRUE.equals(request.noAnalysis)) {
			command.add("-noanalysis");
		}
		if (request.analysisTimeoutPerFileSec != null) {
			command.add("-analysisTimeoutPerFile");
			command.add(String.valueOf(request.analysisTimeoutPerFileSec));
		}
		if (request.maxCpu != null) {
			command.add("-max-cpu");
			command.add(String.valueOf(request.maxCpu));
		}
		appendScriptPaths(command, "-scriptPath", request.scriptPath);
		appendScriptPaths(command, "-propertiesPath", request.propertiesPath);
		appendScripts(command, "-preScript", request.preScripts);
		appendScripts(command, "-postScript", request.postScripts);
		return command;
	}

	private void appendScriptPaths(List<String> command, String flag, List<String> paths) {
		if (paths == null || paths.isEmpty()) {
			return;
		}
		command.add(flag);
		command.add(String.join(";", paths));
	}

	private void appendScripts(List<String> command, String flag, List<ScriptSpec> scripts) {
		if (scripts == null) {
			return;
		}
		for (ScriptSpec script : scripts) {
			command.add(flag);
			command.add(script.name);
			if (script.args != null) {
				command.addAll(script.args);
			}
		}
	}
}
