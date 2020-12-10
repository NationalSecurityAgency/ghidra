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
package ghidra.async;

import static org.junit.Assert.assertEquals;

import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import ghidra.async.AsyncRace;

public class AsyncRaceTest {
	@Test
	public void testAlternateCompleted() {
		AsyncRace<Integer> race = new AsyncRace<>();
		race.include(CompletableFuture.completedFuture(1));
		assertEquals(1, race.next().getNow(null).intValue());
		race.include(CompletableFuture.completedFuture(2));
		assertEquals(2, race.next().getNow(null).intValue());
	}

	@Test
	public void testTwoCompleted() {
		AsyncRace<Integer> race = new AsyncRace<>();
		race.include(CompletableFuture.completedFuture(1));
		race.include(CompletableFuture.completedFuture(2));
		assertEquals(1, race.next().getNow(null).intValue());
		assertEquals(2, race.next().getNow(null).intValue());
	}

	@Test
	public void testTwoDelayed() {
		AsyncRace<Integer> race = new AsyncRace<>();
		CompletableFuture<Integer> c1 = new CompletableFuture<>();
		CompletableFuture<Integer> c2 = new CompletableFuture<>();
		race.include(c1);
		race.include(c2);
		c1.complete(1);
		c2.complete(2);
		assertEquals(1, race.next().getNow(null).intValue());
		assertEquals(2, race.next().getNow(null).intValue());
	}

	@Test
	public void testTwoDelayedReversed() {
		AsyncRace<Integer> race = new AsyncRace<>();
		CompletableFuture<Integer> c1 = new CompletableFuture<>();
		CompletableFuture<Integer> c2 = new CompletableFuture<>();
		race.include(c1);
		race.include(c2);
		c2.complete(2);
		c1.complete(1);
		assertEquals(2, race.next().getNow(null).intValue());
		assertEquals(1, race.next().getNow(null).intValue());
	}
}
