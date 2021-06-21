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
package ghidra.dbg.jdi.manager;

/**
 * A listener for target console output
 * 
 * Note the details of this listener are not well established, for lack of examples that use JDI's
 * target output record.
 */
public interface JdiTargetOutputListener {
	/**
	 * The target outputted some text
	 * 
	 * @param out the output
	 */
	void output(String out);
}
