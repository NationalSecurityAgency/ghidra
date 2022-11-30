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
 * Loads all the system theme.property files that contain all the default color, font, and
 * icon values.
 */
public interface ThemeDefaultsProvider {

	/**
	 * Returns the standard defaults {@link GThemeValueMap}
	 * @return the standard defaults {@link GThemeValueMap}
	 */
	public GThemeValueMap getDefaults();

	/**
	 * Returns the dark defaults {@link GThemeValueMap}
	 * @return the dark defaults {@link GThemeValueMap}
	 */
	public GThemeValueMap getDarkDefaults();

	/**
	 * Returns the defaults specific to a given Look and Feel
	 * @param lafType the Look and Feel type
	 * @return  the defaults specific to a given Look and Feel
	 */
	public GThemeValueMap getLookAndFeelDefaults(LafType lafType);

}
