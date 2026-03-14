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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

class FakeProjectOps implements GhidraProjectOps {
	@Override
	public void createProject(String projectDirectory, String projectName) throws IOException {
		Files.createDirectories(Paths.get(projectDirectory, projectName));
	}

	@Override
	public void validateProjectOpen(String projectDirectory, String projectName) throws IOException {
		if (!projectExists(projectDirectory, projectName)) {
			throw new ApiException(404, "PROJECT_NOT_FOUND",
				"The requested project could not be found.");
		}
	}

	@Override
	public boolean projectExists(String projectDirectory, String projectName) {
		return Files.isDirectory(Paths.get(projectDirectory, projectName));
	}
}

class FakeExecutionEngine implements HeadlessExecutionEngine {
	volatile boolean cancelled;
	volatile long sleepMs;
	volatile int exitCode;

	FakeExecutionEngine() {
		this(0, 0);
	}

	FakeExecutionEngine(long sleepMs, int exitCode) {
		this.sleepMs = sleepMs;
		this.exitCode = exitCode;
	}

	@Override
	public ExecutionOutcome run(ProjectRecord project, JobRecord job, Path jobDir,
			ImportAnalyzeRequest request, ExecutionListener listener) throws Exception {
		Path artifactsDir = jobDir.resolve("artifacts");
		Files.createDirectories(artifactsDir);
		listener.onProgress("import", "Importing test binary", 25);
		Files.writeString(artifactsDir.resolve("application.log"), "app-log\n", StandardCharsets.UTF_8);
		Files.writeString(artifactsDir.resolve("script.log"), "script-log\n", StandardCharsets.UTF_8);
		Files.writeString(artifactsDir.resolve("process-output.log"), "process-log\n",
			StandardCharsets.UTF_8);
		if (sleepMs > 0) {
			Thread.sleep(sleepMs);
		}
		if (cancelled) {
			return new ExecutionOutcome(1, true);
		}
		listener.onLog("stdout", "job finished");
		return new ExecutionOutcome(exitCode, false);
	}

	@Override
	public void cancel(JobRecord job) {
		cancelled = true;
		job.cancelRequested = true;
	}
}
