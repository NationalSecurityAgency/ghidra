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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;

public class TestMimickJavaLauncher
		extends DefaultTestTargetObject<TestTargetObject, TestTargetObject>
		implements TargetLauncher {

	public TestMimickJavaLauncher(TestTargetObject parent) {
		super(parent, "Java Launcher", "Launcher");

		setAttributes(
			List.of(), Map.of(TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetParameterMap.ofEntries(
				Map.entry("Home",
					ParameterDescription.create(String.class, "Home", false,
						"/opt/java-17-amazon-corretto", "Home", "")),
				Map.entry("Launcher",
					ParameterDescription.create(String.class, "Launcher", false, "java", "Launcher",
						"")),
				Map.entry("Main",
					ParameterDescription.create(String.class, "Main", false, "hw.HelloWorld",
						"Main", "")),
				Map.entry("Options",
					ParameterDescription.create(String.class, "Options", false, "", "Options", "")),
				Map.entry("Suspend",
					ParameterDescription.create(Boolean.class, "Suspend", false, true, "Suspend",
						"")),
				Map.entry("Quote",
					ParameterDescription.create(String.class, "Quote", false, "\"", "Quote", "")))),
			"Initialized");
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return AsyncUtils.NIL; // TODO: Queue and allow test to complete it?
	}
}
