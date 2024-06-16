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
package ghidra.program.model.reloc;

import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation.Status;

/**
 * {@link RelocationResult} provides the status and byte-length of a processed relocation during
 * the {@link Program} load process.  Intended to be used internally by a relocation handler.  
 * A positive byte-length is only required for a status of {@link Status#APPLIED} or 
 * {@link Status#APPLIED_OTHER}.  Use if {@link Status#UNKNOWN} should be avoided and is intended
 * for relocation data upgrades when actual status can not be determined.
 * <br>
 * Singleton instances are provided for relocations which did not directly results in original
 * loaded memory modification.
 * 
 * @param status the relocation status
 * @param byteLength the number of original bytes modified at relocation offset if successfully
 * applied and memory bytes were modified.
 */
public record RelocationResult(Status status, int byteLength) {

	/**
	 * See {@link Status#FAILURE}
	 */
	public static final RelocationResult FAILURE = new RelocationResult(Status.FAILURE, 0);

	/**
	 * See {@link Status#UNSUPPORTED}
	 */
	public static final RelocationResult UNSUPPORTED = new RelocationResult(Status.UNSUPPORTED, 0);

	/**
	 * See {@link Status#SKIPPED}
	 */
	public static final RelocationResult SKIPPED = new RelocationResult(Status.SKIPPED, 0);

	/**
	 * See {@link Status#PARTIAL}
	 */
	public static final RelocationResult PARTIAL = new RelocationResult(Status.PARTIAL, 0);

}
