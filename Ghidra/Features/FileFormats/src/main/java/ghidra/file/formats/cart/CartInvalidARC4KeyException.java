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
package ghidra.file.formats.cart;

/**
 * CartInvalidCartException subclass for apparent ARC4 key errors; for instance,
 * when decrypted data does not meet the expected format.
 */
public class CartInvalidARC4KeyException extends CartInvalidCartException {

	/**
	 * Construct CartInvalidARC4KeyException with specified message
	 * @param message The reason for the exception
	 */
	public CartInvalidARC4KeyException(String message) {
		super(message);
	}
}
