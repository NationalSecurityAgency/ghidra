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
package help.screenshot;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.junit.rules.TestName;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.MergeTestFacilitator;

public class MergeScreenShotGenerator extends GhidraScreenShotGenerator {

	protected MergeTestFacilitator mtf;
	private String testFilename;

	public MergeScreenShotGenerator(String testFilename, String testNameStr,
			MergeTestFacilitator mtf, TestName testName) {
		super();
		this.testName = testName;
		this.testFilename = testFilename;
		this.mtf = mtf;
		
	}

	@Override
	public void setUp() {
		env = mtf.getTestEnvironment();
	}

	public void setTool(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	// overridden so that we use the outer class's name when finding the help topic 
	protected File getHelpTopic() {
		String simpleName = testFilename.replace("ScreenShots", "");
		File helpTopicDir = getHelpTopicDir(simpleName);
		assertNotNull("Unable to find help topic for test file: " + testFilename, helpTopicDir);
		return helpTopicDir;
	}
}
