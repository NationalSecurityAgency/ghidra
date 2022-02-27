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
package ghidra.app.util.bin.format.macho.dyld;

/**
 * A convenience interface for getting the address and path of a DYLD Cache image
 */
public interface DyldCacheImage {

	/**
	 * Gets the address the start of the image
	 * 
	 * @return The address of the start of the image
	 */
	public long getAddress();

	/**
	 * Gets the path of the image
	 * 
	 * @return The path of the image
	 */
	public String getPath();
}
