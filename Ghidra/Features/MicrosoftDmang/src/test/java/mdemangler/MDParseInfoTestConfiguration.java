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
package mdemangler;

/**
 * This class is a derivation of MDBaseTestConfiguration (see javadoc there).  This
 *  class must choose the appropriate truth from MDMangBaseTest (new truths might
 *  need to be added there) and override the appropriate helper methods of
 *  MDBaseTestConfiguration.  This specific test configuration is for the purpose
 *  of driving the tests of MDMangParseInfoTest.
 */
public class MDParseInfoTestConfiguration extends MDBaseTestConfiguration {

	public MDParseInfoTestConfiguration(boolean quiet) {
		super(quiet);
		mdm = new MDMangParseInfo();
	}

	@Override
	protected void doExtraProcCheck() throws Exception {
		outputInfo.append(((MDMangParseInfo) mdm).getParseInfoIncremental());
	}
}
