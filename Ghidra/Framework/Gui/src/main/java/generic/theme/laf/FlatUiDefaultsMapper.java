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
	protected void registerIgnoredJavaIds() {
		super.registerIgnoredJavaIds();
		ignoredJavaIds.add("Actions.Blue");
		ignoredJavaIds.add("Actions.Green");
		ignoredJavaIds.add("Actions.Grey");
		ignoredJavaIds.add("Actions.Greyinline");
		ignoredJavaIds.add("Actions.Red");
		ignoredJavaIds.add("Actions.Yellow");

		ignoredJavaIds.add("Objects.BlackText");
		ignoredJavaIds.add("Objects.Blue");
		ignoredJavaIds.add("Objects.Green");
		ignoredJavaIds.add("Objects.GreenAndroid");
		ignoredJavaIds.add("Objects.Grey");
		ignoredJavaIds.add("Objects.Pink");
		ignoredJavaIds.add("Objects.Purple");
		ignoredJavaIds.add("Objects.Red");
		ignoredJavaIds.add("Objects.RedStatus");
		ignoredJavaIds.add("Objects.Yellow");
		ignoredJavaIds.add("Objects.YellowDark");

		ignoredJavaIds.add("h0.font");
		ignoredJavaIds.add("h00.font");
		ignoredJavaIds.add("h1.font");
		ignoredJavaIds.add("h1.regular.font");
		ignoredJavaIds.add("h2.font");
		ignoredJavaIds.add("h2.regular.font");
		ignoredJavaIds.add("h3.font");
		ignoredJavaIds.add("h3.regular.font");
		ignoredJavaIds.add("h4.font");
		ignoredJavaIds.add("large.font");
		ignoredJavaIds.add("light.font");
		ignoredJavaIds.add("medium.font");
		ignoredJavaIds.add("mini.font");
		ignoredJavaIds.add("monospaced.font");
		ignoredJavaIds.add("small.font");

	}
}
