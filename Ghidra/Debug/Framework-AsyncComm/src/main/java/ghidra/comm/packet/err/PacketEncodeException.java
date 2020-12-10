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
package ghidra.comm.packet.err;

/**
 * Occurs during encode when the given packet cannot be encoded according to the type's definition
 * 
 * For example, a string field may be limited to a certain length. Or, for dynamically-typed fields,
 * the given value must be of a supported type.
 */
public class PacketEncodeException extends Exception {
	public PacketEncodeException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public PacketEncodeException(String msg) {
		super(msg);
	}
}
