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
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForGdbInferiorActivationTest
		extends AbstractDebuggerModelActivationTest {

	private static final PathPattern INF_PATTERN = new PathPattern(PathUtils.parse("Inferiors[]"));;

	@Override
	protected Set<TargetObject> getActivatableThings() throws Throwable {
		CompletableFuture<?> inf1 = m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1]"));
		CompletableFuture<?> inf2 = m.getAddedWaiter().wait(PathUtils.parse("Inferiors[2]"));
		CompletableFuture<?> inf3 = m.getAddedWaiter().wait(PathUtils.parse("Inferiors[3]"));

		TargetInterpreter interpreter = findInterpreter();
		// The default +2
		waitOn(interpreter.execute("add-inferior"));
		waitOn(interpreter.execute("add-inferior"));

		waitSettled(m.getModel(), 200);

		return Set.of(
			(TargetObject) waitOn(inf1),
			(TargetObject) waitOn(inf2),
			(TargetObject) waitOn(inf3));
	}

	@Override
	protected List<String> getExpectedDefaultActivePath() {
		return PathUtils.parse("Inferiors[1]");
	}

	@Override
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		String index = Unique.assertOne(INF_PATTERN.matchIndices(obj.getPath()));
		waitOn(interpreter.execute("inferior " + index));
	}

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String output = waitOn(interpreter.executeCapture("info inferiors"));
		String line = Unique.assertOne(Stream.of(output.split("\n"))
				.filter(l -> l.trim().startsWith("*"))
				.collect(Collectors.toList())).trim();
		String inferiorId = line.split("\\s+")[1];
		assertEquals(expected.getPath(), INF_PATTERN.applyIndices(inferiorId).getSingletonPath());
	}
}
