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
package generic.theme.laf;

import javax.swing.UIDefaults;

public class FlatUiDefaultsMapper extends UiDefaultsMapper {

	protected FlatUiDefaultsMapper(UIDefaults defaults) {
		super(defaults);
	}

	@Override
	protected void registerIgnoredLafIds() {
		super.registerIgnoredLafIds();
		ignoredLafIds.add("Actions.Blue");
		ignoredLafIds.add("Actions.Green");
		ignoredLafIds.add("Actions.Grey");
		ignoredLafIds.add("Actions.Greyinline");
		ignoredLafIds.add("Actions.Red");
		ignoredLafIds.add("Actions.Yellow");

		ignoredLafIds.add("Objects.BlackText");
		ignoredLafIds.add("Objects.Blue");
		ignoredLafIds.add("Objects.Green");
		ignoredLafIds.add("Objects.GreenAndroid");
		ignoredLafIds.add("Objects.Grey");
		ignoredLafIds.add("Objects.Pink");
		ignoredLafIds.add("Objects.Purple");
		ignoredLafIds.add("Objects.Red");
		ignoredLafIds.add("Objects.RedStatus");
		ignoredLafIds.add("Objects.Yellow");
		ignoredLafIds.add("Objects.YellowDark");

		ignoredLafIds.add("h0.font");
		ignoredLafIds.add("h00.font");
		ignoredLafIds.add("h1.font");
		ignoredLafIds.add("h1.regular.font");
		ignoredLafIds.add("h2.font");
		ignoredLafIds.add("h2.regular.font");
		ignoredLafIds.add("h3.font");
		ignoredLafIds.add("h3.regular.font");
		ignoredLafIds.add("h4.font");
		ignoredLafIds.add("large.font");
		ignoredLafIds.add("light.font");
		ignoredLafIds.add("medium.font");
		ignoredLafIds.add("mini.font");
		ignoredLafIds.add("monospaced.font");
		ignoredLafIds.add("small.font");

	}
}
