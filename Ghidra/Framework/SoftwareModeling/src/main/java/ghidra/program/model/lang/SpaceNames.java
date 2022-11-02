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
package ghidra.program.model.lang;

/**
 * Reserved AddressSpace names across architectures and associated attributes
 */
public class SpaceNames {
	public static final String CONSTANT_SPACE_NAME = "const";	// P-code constants
	public static final String UNIQUE_SPACE_NAME = "unique";	// Temporary p-code registers
	public static final String STACK_SPACE_NAME = "stack";		// Storage for stack relative varnodes
	public static final String JOIN_SPACE_NAME = "join";		// Logical storage for joined varnodes
	public static final String OTHER_SPACE_NAME = "OTHER";		// Other space
	public static final String IOP_SPACE_NAME = "iop";			// Internal p-code reference space
	public static final String FSPEC_SPACE_NAME = "fspec";		// Internal CALL reference

	// must match ConstantSpace::INDEX (see space.hh)
	public static final int CONSTANT_SPACE_INDEX = 0;		// Index for constant space is always 0
	// must match OtherSpace::INDEX (see space.hh)
	public static final int OTHER_SPACE_INDEX = 1;			// Index for other space is always 1

	public static final int UNIQUE_SPACE_SIZE = 4;		// Number of bytes for a unique offset

}
