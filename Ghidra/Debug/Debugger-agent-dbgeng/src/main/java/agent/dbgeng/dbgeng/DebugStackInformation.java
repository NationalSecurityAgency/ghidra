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
package agent.dbgeng.dbgeng;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_STACK_FRAME;

public class DebugStackInformation {

	private int nFrames;
	private DEBUG_STACK_FRAME[] stackFrames;

	public DebugStackInformation(int nFrames, DEBUG_STACK_FRAME[] stackFrames) {
		this.nFrames = nFrames;
		this.stackFrames = stackFrames;
	}

	public int getNumberOfFrames() {
		return nFrames;
	}

	public DEBUG_STACK_FRAME getFrame(int frameNumber) {
		return stackFrames[frameNumber];
	}
}
