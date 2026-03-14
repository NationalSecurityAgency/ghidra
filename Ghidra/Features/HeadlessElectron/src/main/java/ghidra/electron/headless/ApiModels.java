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

import java.time.Instant;
import java.util.*;

import com.google.gson.JsonElement;

class ApiEnvelope {
	static final String PROTOCOL_VERSION = "1.0";

	final String protocolVersion = PROTOCOL_VERSION;
	final String requestId;
	final Object data;
	final ApiError error;

	ApiEnvelope(String requestId, Object data, ApiError error) {
		this.requestId = requestId;
		this.data = data;
		this.error = error;
	}
}

class ApiError {
	final String code;
	final String message;
	final Object details;

	ApiError(String code, String message, Object details) {
		this.code = code;
		this.message = message;
		this.details = details;
	}
}

class ApiException extends RuntimeException {
	final int statusCode;
	final ApiError error;

	ApiException(int statusCode, String code, String message) {
		this(statusCode, code, message, null);
	}

	ApiException(int statusCode, String code, String message, Object details) {
		super(message);
		this.statusCode = statusCode;
		this.error = new ApiError(code, message, details);
	}
}

class ProjectRecord {
	String projectId;
	String name;
	String projectPath;
	String lastOpenedAt;
	String createdAt;
	boolean existsOnDisk;
	boolean isActive;

	static ProjectRecord create(String projectId, String name, String projectPath, boolean existsOnDisk,
			boolean isActive) {
		ProjectRecord record = new ProjectRecord();
		record.projectId = projectId;
		record.name = name;
		record.projectPath = projectPath;
		record.createdAt = Instant.now().toString();
		record.lastOpenedAt = null;
		record.existsOnDisk = existsOnDisk;
		record.isActive = isActive;
		return record;
	}
}

class ScriptSpec {
	String name;
	List<String> args = new ArrayList<>();
}

class ImportAnalyzeRequest {
	String inputPath;
	Boolean recursive;
	Boolean readOnly;
	Boolean noAnalysis;
	Integer analysisTimeoutPerFileSec;
	Integer maxCpu;
	List<ScriptSpec> preScripts = new ArrayList<>();
	List<ScriptSpec> postScripts = new ArrayList<>();
	List<String> scriptPath = new ArrayList<>();
	List<String> propertiesPath = new ArrayList<>();
}

class CreateJobRequest extends ImportAnalyzeRequest {
	String mode;
	String projectPath;
	String projectName;
	String processPattern;
}

class CreateProjectRequest {
	String projectPath;
	String projectName;
}

class OpenProjectRequest {
	String projectId;
	String projectPath;
	String projectName;
}

class JobProgress {
	String phase;
	Integer current;
	Integer total;
	Integer percent;

	JobProgress(String phase, Integer current, Integer total, Integer percent) {
		this.phase = phase;
		this.current = current;
		this.total = total;
		this.percent = percent;
	}
}

class JobResult {
	Integer importedPrograms;
	Integer analyzedPrograms;
	Integer failedPrograms;
	String outputProjectPath;
}

class ArtifactRecord {
	String artifactId;
	String jobId;
	String name;
	String type;
	String contentType;
	long size;
	String createdAt;
	String downloadUrl;
	String filePath;
}

class JobRecord {
	String jobId;
	String state;
	String mode;
	String projectId;
	String createdAt;
	String startedAt;
	String finishedAt;
	ImportAnalyzeRequest request;
	JobProgress progress;
	JobResult result;
	ApiError error;
	List<String> activeArtifactIds = new ArrayList<>();
	volatile boolean cancelRequested;
}

class CapabilityResponse {
	final int maxConcurrency = 1;
	final List<String> transports = List.of("http-json", "sse");
	final List<String> projectEndpoints = List.of("list", "create", "open", "get",
		"import-and-analyze");
	final List<String> jobStates = List.of("queued", "running", "completed", "failed", "cancelled");
	final List<String> artifactTypes = List.of("log", "report", "export", "other");
}

class ServerEvent {
	final long sequence;
	final String eventType;
	final JsonElement payload;

	ServerEvent(long sequence, String eventType, JsonElement payload) {
		this.sequence = sequence;
		this.eventType = eventType;
		this.payload = payload;
	}
}
