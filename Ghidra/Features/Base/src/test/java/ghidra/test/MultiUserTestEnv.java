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
package ghidra.test;

import ghidra.base.project.FakeSharedProject;

/**
 * A TestEnv that allows more than one instance to run at a time.
 */
public class MultiUserTestEnv extends TestEnv {

	public MultiUserTestEnv(FakeSharedProject project) {
		super(project.getGhidraProject());
	}
}
