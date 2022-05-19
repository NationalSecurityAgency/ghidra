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
package agent.frida.model.invm;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import agent.frida.model.AbstractModelForFridaRootAttacherTest;
import generic.test.category.NightlyCategory;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class InVmModelForFridaRootAttacherTest extends AbstractModelForFridaRootAttacherTest {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmFridaModelHost();
	}

	// NB: These tests need debugger rights, which means either:
	//   (1) on macos, codesigning the executables
	//   (2) on linux, "sudo su; echo 0 > /proc/sys/kernel/yama/ptrace_scope"

	@Override
	@Ignore // test requires ability to attach by object & frida version requires pid
	@Test
	public void testAttachByObjBogusThrowsException() throws Throwable {
		super.testAttachByObjBogusThrowsException();
	}

}
