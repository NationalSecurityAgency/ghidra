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
package docking.widgets.table;

import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class HexDefaultGColumnRenderer<T extends Number> extends AbstractGColumnRenderer<T> {
	private final static FormatSettingsDefinition INTEGER_RADIX_SETTING =
		FormatSettingsDefinition.DEF_HEX;

	@Override
	protected int getRadix(Settings settings) {
		return INTEGER_RADIX_SETTING.getRadix(settings);
	}

	@Override
	public String getFilterString(Number t, Settings settings) {
		return formatNumber(t, settings);
	}
}
