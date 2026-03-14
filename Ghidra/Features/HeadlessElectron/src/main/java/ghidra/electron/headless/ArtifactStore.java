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
import java.time.Instant;
import java.util.*;

import com.google.gson.reflect.TypeToken;

class ArtifactStore {
	private final Path jobsRoot;
	private final EventBroker eventBroker;
	private final Map<String, List<ArtifactRecord>> artifactsByJob = new HashMap<>();

	ArtifactStore(Path dataDir, EventBroker eventBroker) throws IOException {
		this.jobsRoot = dataDir.resolve("jobs");
		this.eventBroker = eventBroker;
		Files.createDirectories(jobsRoot);
	}

	synchronized Path ensureJobDir(String jobId) throws IOException {
		Path jobDir = jobsRoot.resolve(jobId);
		Files.createDirectories(jobDir.resolve("artifacts"));
		return jobDir;
	}

	synchronized ArtifactRecord registerArtifact(String jobId, Path file, String type,
			String contentType, boolean inline) throws IOException {
		ensureJobDir(jobId);
		ArtifactRecord record = new ArtifactRecord();
		record.artifactId = "artifact_" + UUID.randomUUID().toString().replace("-", "");
		record.jobId = jobId;
		record.name = file.getFileName().toString();
		record.type = type;
		record.contentType = contentType;
		record.size = Files.exists(file) ? Files.size(file) : 0;
		record.createdAt = Instant.now().toString();
		record.downloadUrl = "/api/v1/jobs/" + jobId + "/artifacts/" + record.artifactId;
		record.filePath = file.toAbsolutePath().toString();
		artifactsByJob.computeIfAbsent(jobId, k -> new ArrayList<>()).add(record);
		save(jobId);
		eventBroker.publish("artifact.created",
			Map.of("jobId", jobId, "timestamp", record.createdAt, "artifact", publicView(record)));
		return record;
	}

	synchronized List<ArtifactRecord> listArtifacts(String jobId) throws IOException {
		loadIfNeeded(jobId);
		List<ArtifactRecord> records = new ArrayList<>(artifactsByJob.getOrDefault(jobId, List.of()));
		records.sort(Comparator.comparing(a -> a.createdAt));
		return records;
	}

	synchronized ArtifactRecord getArtifact(String jobId, String artifactId) throws IOException {
		return listArtifacts(jobId).stream().filter(a -> artifactId.equals(a.artifactId)).findFirst()
				.orElseThrow(() -> new ApiException(404, "ARTIFACT_NOT_FOUND",
					"The requested artifact could not be found.",
					Map.of("jobId", jobId, "artifactId", artifactId)));
	}

	synchronized void writeSummaryArtifact(String jobId, JobResult result) throws IOException {
		Path summaryFile = ensureJobDir(jobId).resolve("artifacts").resolve("summary.json");
		Files.writeString(summaryFile, JsonSupport.GSON.toJson(result), StandardCharsets.UTF_8,
			StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		registerArtifact(jobId, summaryFile, "report", "application/json", false);
	}

	private Object publicView(ArtifactRecord record) {
		Map<String, Object> view = new LinkedHashMap<>();
		view.put("artifactId", record.artifactId);
		view.put("jobId", record.jobId);
		view.put("name", record.name);
		view.put("type", record.type);
		view.put("contentType", record.contentType);
		view.put("size", record.size);
		view.put("createdAt", record.createdAt);
		view.put("downloadUrl", record.downloadUrl);
		return view;
	}

	private void loadIfNeeded(String jobId) throws IOException {
		if (artifactsByJob.containsKey(jobId)) {
			return;
		}
		Path metadata = metadataFile(jobId);
		if (!Files.exists(metadata)) {
			artifactsByJob.put(jobId, new ArrayList<>());
			return;
		}
		List<ArtifactRecord> records = JsonSupport.GSON.fromJson(Files.readString(metadata),
			new TypeToken<List<ArtifactRecord>>() {
			}.getType());
		artifactsByJob.put(jobId, records == null ? new ArrayList<>() : new ArrayList<>(records));
	}

	private void save(String jobId) throws IOException {
		Path metadata = metadataFile(jobId);
		Files.createDirectories(metadata.getParent());
		Files.writeString(metadata,
			JsonSupport.GSON.toJson(artifactsByJob.getOrDefault(jobId, List.of())),
			StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
	}

	private Path metadataFile(String jobId) {
		return jobsRoot.resolve(jobId).resolve("artifacts.json");
	}
}
