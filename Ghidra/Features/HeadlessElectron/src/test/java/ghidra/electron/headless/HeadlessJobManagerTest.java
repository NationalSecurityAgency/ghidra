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

import static org.junit.Assert.*;

import java.nio.file.Path;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class HeadlessJobManagerTest extends AbstractGenericTest {

	@Test
	public void testJobCompletesAndPublishesArtifacts() throws Exception {
		Path tempDir = createTempDirectory("headless-jobs");
		EventBroker broker = new EventBroker();
		ArtifactStore artifactStore = new ArtifactStore(tempDir, broker);
		HeadlessJobManager jobManager =
			new HeadlessJobManager(tempDir, artifactStore, broker, new FakeExecutionEngine());

		ProjectRecord project = ProjectRecord.create("proj_1", "alpha", tempDir.resolve("alpha").toString(),
			true, true);
		ImportAnalyzeRequest request = new ImportAnalyzeRequest();
		request.inputPath = "/bin/ls";

		JobRecord submitted = jobManager.submitImportAnalyze(project, request);
		waitForTerminal(jobManager, submitted.jobId);

		JobRecord job = jobManager.getJob(submitted.jobId);
		assertEquals("completed", job.state);
		List<ArtifactRecord> artifacts = jobManager.listArtifacts(job.jobId);
		assertFalse(artifacts.isEmpty());
		jobManager.shutdown();
	}

	@Test
	public void testActiveJobConflict() throws Exception {
		Path tempDir = createTempDirectory("headless-jobs-busy");
		EventBroker broker = new EventBroker();
		ArtifactStore artifactStore = new ArtifactStore(tempDir, broker);
		HeadlessJobManager jobManager =
			new HeadlessJobManager(tempDir, artifactStore, broker, new FakeExecutionEngine(500, 0));

		ProjectRecord project = ProjectRecord.create("proj_1", "alpha", tempDir.resolve("alpha").toString(),
			true, true);
		ImportAnalyzeRequest request = new ImportAnalyzeRequest();
		request.inputPath = "/bin/ls";
		jobManager.submitImportAnalyze(project, request);

		try {
			jobManager.submitImportAnalyze(project, request);
			fail("Expected active job conflict");
		}
		catch (ApiException e) {
			assertEquals("JOB_ACTIVE", e.error.code);
		}
		finally {
			jobManager.shutdown();
		}
	}

	private void waitForTerminal(HeadlessJobManager manager, String jobId) throws Exception {
		for (int i = 0; i < 50; i++) {
			String state = manager.getJob(jobId).state;
			if ("completed".equals(state) || "failed".equals(state) || "cancelled".equals(state)) {
				return;
			}
			Thread.sleep(50);
		}
		fail("Timed out waiting for terminal job state");
	}
}
