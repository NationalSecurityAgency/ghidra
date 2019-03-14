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

import ghidra.pcodeCPort.space.*;


public class FixedHandle {
  public AddrSpace space;
  public int size;
  public AddrSpace offset_space;	// Either null or where dynamic offset is stored
  public long offset_offset;		// Either static offset or ptr offset
  public int offset_size;		// Size of pointer
  public AddrSpace temp_space;	// Consistent temporary location for value
  public long temp_offset;
}
