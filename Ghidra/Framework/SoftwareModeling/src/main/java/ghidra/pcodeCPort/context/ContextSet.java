/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.context;

import ghidra.pcodeCPort.slghsymbol.*;


public class ContextSet {
  public TripleSymbol sym;		// Resolves to address where setting takes effect
  public ConstructState point;	// Point at which context set was made
  public int num;			// Number of context word affected
  public int mask;			// Bits within word affected
  public int value;			// New setting for bits
  public boolean flow;          // Does the new context flow from its set point
}
