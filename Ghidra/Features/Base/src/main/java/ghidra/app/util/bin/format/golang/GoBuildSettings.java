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
package ghidra.app.util.bin.format.golang;

import java.io.IOException;

/**
 * Key=value element of Golang Build settings
 * 
 * @param key string name of property
 * @param value string value of property
 */
public record GoBuildSettings(String key, String value) {

	/**
	 * Parses a "key=value" string and returns the parts as a {@link GoBuildSettings}.
	 * 
	 * @param s "key=value" string
	 * @return new {@link GoBuildSettings} instance
	 * @throws IOException if error splitting the string into key and value
	 */
	public static GoBuildSettings fromString(String s) throws IOException {
		String[] parts = s.split("=", 2);
		if (parts.length != 2) {
			throw new IOException();
		}
		return new GoBuildSettings(parts[0], parts[1]);
	}
}
