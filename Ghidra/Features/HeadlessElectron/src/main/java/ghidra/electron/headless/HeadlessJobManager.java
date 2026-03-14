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
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

class HeadlessJobManager {
	private final Path dataDir;
	private final ArtifactStore artifactStore;
	private final EventBroker eventBroker;
	private final HeadlessExecutionEngine executionEngine;
	private final ExecutorService executor = Executors.newSingleThreadExecutor();
	private final Map<String, JobRecord> jobs = new ConcurrentHashMap<>();
	private final Map<String, Future<?>> futures = new ConcurrentHashMap<>();
	private volatile String activeJobId;

	HeadlessJobManager(Path dataDir, ArtifactStore artifactStore, EventBroker eventBroker,
			HeadlessExecutionEngine executionEngine) {
		this.dataDir = dataDir;
		this.artifactStore = artifactStore;
		this.eventBroker = eventBroker;
		this.executionEngine = executionEngine;
	}

	void shutdown() {
		executor.shutdownNow();
	}

	synchronized JobRecord submitImportAnalyze(ProjectRecord project, ImportAnalyzeRequest request) {
		validateRequest(request);
		if (activeJobId != null) {
			throw new ApiException(409, "JOB_ACTIVE", "Another headless job is already active.",
				Map.of("activeJobId", activeJobId));
		}
		JobRecord job = new JobRecord();
		job.jobId = "job_" + UUID.randomUUID().toString().replace("-", "");
		job.state = "queued";
		job.mode = "import";
		job.projectId = project.projectId;
		job.createdAt = Instant.now().toString();
		job.request = normalize(request);
		job.progress = new JobProgress("setup", 0, 1, 0);
		jobs.put(job.jobId, job);
		activeJobId = job.jobId;
		eventBroker.publish("job.created", Map.of("jobId", job.jobId, "timestamp", job.createdAt,
			"state", job.state, "mode", job.mode, "projectId", job.projectId, "inputPath",
			job.request.inputPath));
		futures.put(job.jobId, executor.submit(() -> runJob(project, job)));
		return job;
	}

	JobRecord getJob(String jobId) {
		JobRecord job = jobs.get(jobId);
		if (job == null) {
			throw new ApiException(404, "JOB_NOT_FOUND", "The requested job could not be found.",
				Map.of("jobId", jobId));
		}
		return job;
	}

	synchronized void cancelJob(String jobId) {
		JobRecord job = getJob(jobId);
		if (isTerminal(job.state)) {
			throw new ApiException(409, "CANCEL_NOT_ALLOWED",
				"The requested job can not be cancelled.", Map.of("jobId", jobId, "state", job.state));
		}
		job.cancelRequested = true;
		executionEngine.cancel(job);
	}

	List<ArtifactRecord> listArtifacts(String jobId) throws IOException {
		getJob(jobId);
		return artifactStore.listArtifacts(jobId);
	}

	ArtifactRecord getArtifact(String jobId, String artifactId) throws IOException {
		getJob(jobId);
		return artifactStore.getArtifact(jobId, artifactId);
	}

	private void runJob(ProjectRecord project, JobRecord job) {
		try {
			Path jobDir = artifactStore.ensureJobDir(job.jobId);
			job.state = "running";
			job.startedAt = Instant.now().toString();
			job.progress = new JobProgress("setup", 0, 1, 5);
			eventBroker.publish("job.started", Map.of("jobId", job.jobId, "timestamp", job.startedAt,
				"state", job.state, "mode", job.mode, "projectId", job.projectId));

			ExecutionListener listener = new ExecutionListener() {
				@Override
				public void onProgress(String phase, String message, Integer percent) {
					job.progress = new JobProgress(phase, 1, 1, percent);
					eventBroker.publish("job.progress",
						Map.of("jobId", job.jobId, "timestamp", Instant.now().toString(), "state",
							job.state, "message", message, "progress", job.progress));
				}

				@Override
				public void onLog(String stream, String message) {
					eventBroker.publish("job.log",
						Map.of("jobId", job.jobId, "timestamp", Instant.now().toString(), "stream",
							stream, "message", message));
				}
			};

			ExecutionOutcome outcome = executionEngine.run(project, job, jobDir, job.request, listener);
			registerDefaultArtifacts(job.jobId, jobDir);
			if (outcome.cancelled) {
				job.state = "cancelled";
				job.finishedAt = Instant.now().toString();
				job.progress = new JobProgress("finalize", 1, 1, 100);
				eventBroker.publish("job.cancelled",
					Map.of("jobId", job.jobId, "timestamp", job.finishedAt, "state", job.state,
						"message", "Job cancelled by user"));
			}
			else if (outcome.exitCode == 0) {
				job.state = "completed";
				job.finishedAt = Instant.now().toString();
				job.progress = new JobProgress("finalize", 1, 1, 100);
				job.result = new JobResult();
				job.result.importedPrograms = 1;
				job.result.analyzedPrograms = Boolean.TRUE.equals(job.request.noAnalysis) ? 0 : 1;
				job.result.failedPrograms = 0;
				job.result.outputProjectPath = project.projectPath;
				artifactStore.writeSummaryArtifact(job.jobId, job.result);
				registerArtifactIds(job.jobId);
				eventBroker.publish("job.completed",
					Map.of("jobId", job.jobId, "timestamp", job.finishedAt, "state", job.state,
						"message", "Import and analysis finished", "result", job.result));
			}
			else {
				job.state = "failed";
				job.finishedAt = Instant.now().toString();
				job.error = new ApiError("HEADLESS_EXEC_FAILED",
					"Analyzer process exited non-zero", Map.of("exitCode", outcome.exitCode));
				registerArtifactIds(job.jobId);
				eventBroker.publish("job.failed",
					Map.of("jobId", job.jobId, "timestamp", job.finishedAt, "state", job.state,
						"message", "Headless execution failed", "error", job.error));
			}
		}
		catch (Exception e) {
			job.state = "failed";
			job.finishedAt = Instant.now().toString();
			job.error = new ApiError("INTERNAL_ERROR", "Unexpected job failure",
				Map.of("message", e.getMessage()));
			eventBroker.publish("job.failed",
				Map.of("jobId", job.jobId, "timestamp", job.finishedAt, "state", job.state,
					"message", "Unexpected job failure", "error", job.error));
		}
		finally {
			activeJobId = null;
		}
	}

	private void validateRequest(ImportAnalyzeRequest request) {
		Map<String, String> fieldErrors = new LinkedHashMap<>();
		if (request == null) {
			throw new ApiException(400, "INVALID_REQUEST", "Request body is required.");
		}
		if (request.inputPath == null || request.inputPath.isBlank()) {
			fieldErrors.put("inputPath", "Path is required");
		}
		else if (!Files.exists(Paths.get(request.inputPath))) {
			fieldErrors.put("inputPath", "Path does not exist");
		}
		if (request.analysisTimeoutPerFileSec != null && request.analysisTimeoutPerFileSec <= 0) {
			fieldErrors.put("analysisTimeoutPerFileSec", "Must be positive");
		}
		if (request.maxCpu != null && request.maxCpu <= 0) {
			fieldErrors.put("maxCpu", "Must be positive");
		}
		if (!fieldErrors.isEmpty()) {
			throw new ApiException(422, "VALIDATION_ERROR", "The request failed validation.",
				Map.of("fields", fieldErrors));
		}
	}

	private ImportAnalyzeRequest normalize(ImportAnalyzeRequest request) {
		ImportAnalyzeRequest normalized = new ImportAnalyzeRequest();
		normalized.inputPath = request.inputPath;
		normalized.recursive = Boolean.TRUE.equals(request.recursive);
		normalized.readOnly = Boolean.TRUE.equals(request.readOnly);
		normalized.noAnalysis = Boolean.TRUE.equals(request.noAnalysis);
		normalized.analysisTimeoutPerFileSec = request.analysisTimeoutPerFileSec;
		normalized.maxCpu = request.maxCpu;
		normalized.preScripts =
			request.preScripts == null ? new ArrayList<>() : new ArrayList<>(request.preScripts);
		normalized.postScripts =
			request.postScripts == null ? new ArrayList<>() : new ArrayList<>(request.postScripts);
		normalized.scriptPath =
			request.scriptPath == null ? new ArrayList<>() : new ArrayList<>(request.scriptPath);
		normalized.propertiesPath = request.propertiesPath == null ? new ArrayList<>()
				: new ArrayList<>(request.propertiesPath);
		return normalized;
	}

	private boolean isTerminal(String state) {
		return "completed".equals(state) || "failed".equals(state) || "cancelled".equals(state);
	}

	private void registerDefaultArtifacts(String jobId, Path jobDir) throws IOException {
		Path artifactsDir = jobDir.resolve("artifacts");
		registerIfExists(jobId, artifactsDir.resolve("application.log"), "log", "text/plain");
		registerIfExists(jobId, artifactsDir.resolve("script.log"), "log", "text/plain");
		registerIfExists(jobId, artifactsDir.resolve("process-output.log"), "log", "text/plain");
	}

	private void registerIfExists(String jobId, Path file, String type, String contentType)
			throws IOException {
		if (Files.exists(file)) {
			artifactStore.registerArtifact(jobId, file, type, contentType, true);
		}
	}

	private void registerArtifactIds(String jobId) throws IOException {
		JobRecord job = getJob(jobId);
		job.activeArtifactIds =
			artifactStore.listArtifacts(jobId).stream().map(a -> a.artifactId).toList();
	}
}
