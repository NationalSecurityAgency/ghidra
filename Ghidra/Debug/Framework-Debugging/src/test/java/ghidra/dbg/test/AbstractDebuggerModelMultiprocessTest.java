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
package ghidra.dbg.test;

/**
 * TODO: We need more tests to verify that commands affect the specified thing.
 * Some models seem to just use the "current," which is <em>usually</em> correct
 * in practice because of focus syncing, but it may not be, esp., if the user is
 * scripting. In particular, when it comes to actions on processes and threads:
 * 
 * <ul>
 * <li>Process.kill</li>
 * <li>Process.detach</li>
 * <li>Thread.step</li>
 * </ul>
 */
public class AbstractDebuggerModelMultiprocessTest {

}
