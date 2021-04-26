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
package agent.gdb.model;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForGdbThreadActivationTest
		extends AbstractDebuggerModelActivationTest {

	private static final PathPattern THREAD_PATTERN =
		new PathPattern(PathUtils.parse("Inferiors[].Threads[]"));

	protected DebuggerTestSpecimen getSpecimen() {
		return GdbLinuxSpecimen.PRINT;
	}

	@Override
	protected Set<TargetObject> getActivatableThings() throws Throwable {
		/**
		 * TODO: GDB should really use the 1.1 and 2.1 numbering instead of the GId, but I don't
		 * know a good way via GDB/MI to obtain the thread's per-inferior Id.
		 * 
		 * NB: A lot of the test takes advantage of the iid and tid being the same. Don't try to
		 * apply the pattern matching used here in other contexts.
		 */
		CompletableFuture<?> inf1 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1].Threads[1]"));
		CompletableFuture<?> inf2 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[2].Threads[2]"));

		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher(); // root launcher should generate new inferiors
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		waitOn(launcher.launch(specimen.getLauncherArgs()));

		waitSettled(m.getModel(), 200);

		return Set.of(
			(TargetObject) waitOn(inf1),
			(TargetObject) waitOn(inf2));
	}

	@Override
	protected List<String> getExpectedDefaultActivePath() {
		return PathUtils.parse("Inferiors[2].Threads[2].Stack[0]");
	}

	@Override
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		String index = Unique.assertOne(Set.copyOf(THREAD_PATTERN.matchIndices(obj.getPath())));
		// TODO: This test is imperfect, since inferiors are activated as well
		waitOn(interpreter.execute("thread " + index + ".1"));
	}

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String output = waitOn(interpreter.executeCapture("info threads -gid"));
		String line = Unique.assertOne(Stream.of(output.split("\n"))
				.filter(l -> l.trim().startsWith("*"))
				.collect(Collectors.toList()));
		String threadGid = line.split("\\s+")[2];
		assertEquals(expected.getPath(),
			THREAD_PATTERN.applyIndices(threadGid, threadGid).getSingletonPath());
	}
}
