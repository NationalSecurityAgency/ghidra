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
package ghidra.app.plugin.core.progmgr;

import static org.junit.Assert.*;

import java.time.Duration;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class ProgramCacheTest extends AbstractGhidraHeadlessIntegrationTest {
	private static long KEEP_TIME = 100;
	private static int MAX_SIZE = 4;

	private ProgramCache cache;
	private Program program;
	private ProgramLocator locator;

	@Before
	public void setup() throws Exception {
		cache = new ProgramCache(Duration.ofMillis(KEEP_TIME), MAX_SIZE);
		program = buildProgram();
		locator = new ProgramLocator(program.getDomainFile());
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test Program", ProgramBuilder._TOY, this);
		return builder.getProgram();
	}

	@Test
	public void testCacheReleasesProgramWithNoOtherConsumers() {
		assertFalse(program.isClosed());
		cache.put(locator, program);
		program.release(this);		// close the only other consumer besides cache

		assertEquals(1, cache.size());
		assertFalse(program.isClosed());
		sleep(110);
		assertEquals(0, cache.size());
		assertTrue(program.isClosed());
	}

	@Test
	public void testCacheDoesNotReleaseProgramWhenOtherConsumersExist() {
		assertFalse(program.isClosed());
		cache.put(locator, program);

		assertEquals(1, cache.size());
		assertFalse(program.isClosed());
		sleep(110);
		assertEquals(1, cache.size());
		assertFalse(program.isClosed());

		program.release(this);		// close the only other consumer besides cache
		sleep(110);
		assertEquals(0, cache.size());
		assertTrue(program.isClosed());

	}

	@Test
	public void testAddingProgramTwiceOnlyAddsConsumerOnce() {
		cache.put(locator, program);
		cache.put(locator, program);
		cache.put(locator, program);
		program.release(this);			// release this so as to not confuse the issue

		assertEquals(1, program.getConsumerList().size());
		sleep(110);
		assertEquals(0, cache.size());
		assertTrue(program.isClosed());

	}

	@Test
	public void testTooManuProgramsRemovesOldest() throws Exception {
		cache.put(locator, program);

		Program p1 = buildProgram();
		cache.put(new ProgramLocator(p1.getDomainFile()), p1);
		Program p2 = buildProgram();
		cache.put(new ProgramLocator(p2.getDomainFile()), p2);
		Program p3 = buildProgram();
		cache.put(new ProgramLocator(p3.getDomainFile()), p3);

		assertEquals(2, program.getConsumerList().size());

		Program p4 = buildProgram();
		cache.put(new ProgramLocator(p4.getDomainFile()), p4);

		// program should have been kicked out as the cache size is only 4
		assertEquals(1, program.getConsumerList().size());

	}

}
