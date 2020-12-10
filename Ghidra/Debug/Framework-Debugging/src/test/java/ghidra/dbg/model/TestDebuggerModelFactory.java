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
package ghidra.dbg.model;

import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;

@FactoryDescription(brief = "Mocked Client", htmlDetails = TestDebuggerModelFactory.FAKE_DETAILS)
public class TestDebuggerModelFactory implements DebuggerModelFactory {
	public static final String FAKE_DETAILS = "A 'connection' to a fake debugger";
	public static final String FAKE_DETAILS_HTML =
		"<html><b>Description:</b> A&nbsp;'connection'&nbsp;to&nbsp;a&nbsp;fake&nbsp;debugger";
	public static final String FAKE_OPTION_NAME = "Test String";
	public static final String FAKE_DEFAULT = "Default test string";

	protected final Deque<CompletableFuture<DebuggerObjectModel>> buildQueue =
		new LinkedList<>();

	@FactoryOption(FAKE_OPTION_NAME)
	public final Property<String> testStringOption =
		Property.fromAccessors(String.class, this::getTestString, this::setTestString);

	private String testString = FAKE_DEFAULT;

	public TestDebuggerModelFactory() {
	}

	public String getTestString() {
		return testString;
	}

	public void setTestString(String testString) {
		this.testString = testString;
	}

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		CompletableFuture<DebuggerObjectModel> future = new CompletableFuture<>();
		buildQueue.offer(future);
		return future;
	}

	public CompletableFuture<DebuggerObjectModel> pollBuild() {
		return buildQueue.poll();
	}
}
