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
// Shows how to set continuation option for headless analyzer. This option allows the script to tell
// the headless analyzer what to do next (abort processing for this program?  delete program?).  The
// default option is "CONTINUE".
//
// See the 'analyzeHeadlessREADME.html' file for more details about continuation options.
//
//@category Examples

import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.Msg;

public class SetHeadlessContinuationOptionScript extends HeadlessScript {

	@Override
	protected void run() throws Exception {

		if (isRunningHeadless()) {

			Msg.info(this, "At beginning of script, state is: " + getHeadlessContinuationOption());

			setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE_THEN_DELETE);

			// Options to choose from are:
			//  HeadlessContinuationOption.ABORT_AND_DELETE
			//	HeadlessContinuationOption.ABORT
			//  HeadlessContinuationOption.CONTINUE_THEN_DELETE
			//	HeadlessContinuationOption.CONTINUE

			Msg.info(this, "At end of script, state is: " + getHeadlessContinuationOption());
		}

	}
}
