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

import java.awt.Color;

import javax.swing.UIDefaults;
import javax.swing.plaf.UIResource;

/**
 * Version of GColor that implements UIResource. It is important that when setting java defaults
 * in the {@link UIDefaults} that it implements UIResource. Otherwise, java will think the color
 * was set explicitly by client code and therefore can't update it generically when it goes to 
 * update the default color in the UIs for each component.
 */
public class GColorUIResource extends GColor implements UIResource {

	public GColorUIResource(String id) {
		super(id);
	}

	/**
	 * Returns a non-UIResource GColor for this GColorUiResource's id
	 * @return a non-UIResource GColor for this GColorUiResource's id
	 */
	public Color toGColor() {
		return new GColor(getId());
	}

}
