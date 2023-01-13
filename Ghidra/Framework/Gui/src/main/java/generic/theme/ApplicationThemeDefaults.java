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
package generic.theme;

/**
 * Provides theme default values, such as those loaded from {@code *.theme.property} files.
 */
public interface ApplicationThemeDefaults {

	/**
	 * Returns the light default {@link GThemeValueMap}
	 * @return the light default {@link GThemeValueMap}
	 */
	public GThemeValueMap getLightValues();

	/**
	 * Returns the dark default {@link GThemeValueMap}
	 * @return the dark default {@link GThemeValueMap}
	 */
	public GThemeValueMap getDarkValues();

	/**
	 * Returns the default values specific to a given Look and Feel
	 * @param lafType the Look and Feel type
	 * @return the default values specific to a given Look and Feel
	 */
	public GThemeValueMap getLookAndFeelValues(LafType lafType);

}
