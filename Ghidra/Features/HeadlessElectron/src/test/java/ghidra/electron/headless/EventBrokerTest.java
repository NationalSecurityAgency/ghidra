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

import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

public class EventBrokerTest {

	@Test
	public void testSubscribeReceivesReplayAndNewEvents() throws Exception {
		EventBroker broker = new EventBroker();
		broker.publish("project.created", Map.of("projectId", "p1"));
		broker.publish("job.created", Map.of("jobId", "j1"));

		try (EventBroker.EventSubscription subscription = broker.subscribe(0)) {
			ServerEvent first = subscription.poll(1, TimeUnit.SECONDS);
			ServerEvent second = subscription.poll(1, TimeUnit.SECONDS);
			assertEquals("project.created", first.eventType);
			assertEquals("job.created", second.eventType);

			broker.publish("job.completed", Map.of("jobId", "j1"));
			ServerEvent third = subscription.poll(1, TimeUnit.SECONDS);
			assertEquals("job.completed", third.eventType);
		}
	}
}
