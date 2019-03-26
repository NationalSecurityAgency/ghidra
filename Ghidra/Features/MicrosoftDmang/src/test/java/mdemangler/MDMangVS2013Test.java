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
 * This class is a derivation of MDMangBaseTest.  It has a corresponding test
 *  configuration class that is derived from MDBastTestConfiguration and is
 *  allocated below.  The purpose of this class is to perform testing of a
 *  demangler that is a derivation of MDMang using tests that are codified
 *  in MDMangBaseTest (note that new versions of "truth" might need to be
 *  added to MDMang for any new, desired demangler output).  In this case,
 *  this class is testing MDMangVS2013 demangler.
 */
public class MDMangVS2013Test extends MDMangBaseTest {
	public MDMangVS2013Test() {
		testConfiguration = new MDVS2013TestConfiguration(beQuiet());
	}
}
