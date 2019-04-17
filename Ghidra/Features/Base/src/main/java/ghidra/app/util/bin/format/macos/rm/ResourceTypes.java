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
package ghidra.app.util.bin.format.macos.rm;

public interface ResourceTypes {
	/**
	 * Resource Type ID for the Code Fragment Manager (CFM).
	 * */
	public final static int TYPE_CFRG      = 0x63667267;//'c' 'f' 'r' 'g'

	public final static int TYPE_STR_SPACE = 0x53545220;//'s' 't' 'r' ' '

	public final static int TYPE_STR_POUND = 0x53545223;//'s' 't' 'r' '#'

	public final static int TYPE_ICON      = 0x49434E23;//'I' 'C' 'N' '#'

}
