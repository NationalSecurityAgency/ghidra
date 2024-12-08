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
package ghidra.bsfv;

public enum BSimFeatureType {
	// Signature describes data-flow to a single varnode
	DATA_FLOW,

	// Signature describes control-flow for a basic-block
	CONTROL_FLOW,

	// Signature describes control-flow for a basic-block and
	// data-flow into the first (root) PcodeOp in the block
	COMBINED,

	// Signature describes data-flow into two root PcodeOps
	// that are adjacent in a basic-block
	DUAL_FLOW,

	// Signature describes stand-alone COPY ops within a single block
	COPY_SIG
}
