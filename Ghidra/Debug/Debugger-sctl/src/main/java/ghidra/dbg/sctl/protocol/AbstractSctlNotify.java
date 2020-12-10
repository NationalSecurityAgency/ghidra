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
package ghidra.dbg.sctl.protocol;

/**
 * A base class for all {@code A}-type SCTL messages
 * 
 * There is only one {@code A}-type message, so this class exists to follow the same convention as
 * the {@code T}- and {@code R}-type messages.
 */
public abstract class AbstractSctlNotify extends SctlPacket {
	// Empty
}
