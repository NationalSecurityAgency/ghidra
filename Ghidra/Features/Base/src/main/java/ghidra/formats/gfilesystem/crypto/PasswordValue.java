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
package ghidra.formats.gfilesystem.crypto;

import java.io.Closeable;
import java.util.Arrays;

/**
 * Wrapper for a password, held in a char[] array.
 * <p>
 * {@link #close() Closing} an instance will clear the characters of the char array.
 */
public class PasswordValue implements Closeable {

	/**
	 * Creates a new PasswordValue using a copy the specified characters.
	 * 
	 * @param password password characters
	 * @return new PasswordValue instance
	 */
	public static PasswordValue copyOf(char[] password) {
		PasswordValue result = new PasswordValue();
		result.password = new char[password.length];
		System.arraycopy(password, 0, result.password, 0, password.length);
		return result;
	}

	/**
	 * Creates a new PasswordValue by wrapping the specified character array.
	 * <p>
	 * The new instance will take ownership of the char array, and
	 * clear it when the instance is {@link #close() closed}.
	 * 
	 * @param password password characters
	 * @return new PasswordValue instance
	 */
	public static PasswordValue wrap(char[] password) {
		PasswordValue result = new PasswordValue();
		result.password = password;
		return result;
	}

	private char[] password;

	private PasswordValue() {
		// empty
	}

	@Override
	public PasswordValue clone() {
		return copyOf(password);
	}

	/**
	 * Clears the password characters by overwriting them with '\0's.
	 */
	@Override
	public void close() {
		Arrays.fill(password, '\0');
		password = null;
	}

	/**
	 * Returns a reference to the current password characters.
	 * 
	 * @return reference to the current password characters
	 */
	public char[] getPasswordChars() {
		return password;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(password);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PasswordValue other = (PasswordValue) obj;
		return Arrays.equals(password, other.password);
	}

}
