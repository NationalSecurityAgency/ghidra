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
package docking.widgets.fieldpanel.listener;

import java.math.BigInteger;

import docking.widgets.fieldpanel.FieldPanel;

/**
 * Interface for mapping indexes when the LayoutModel changes. In other words, if the mapping
 * of layout indexes to some data model changes and you want the {@link FieldPanel} to continue
 * to display the same model data on the screen, the IndexMapper can be used to convert old
 * indexes to new indexes.
 */
public interface IndexMapper {
	public static final IndexMapper IDENTITY_MAPPER = new IndexMapper() {
		@Override
		public BigInteger map(BigInteger value) {
			return value;
		}
	};

	/**
	 * Maps an index from one address mapping to another. This method will return
	 * {@link BigInteger#ZERO} if there no mapping. 
	 * @param value the index value to map from an old index map to a new index map
	 * @return the mapped index
	 */
	public BigInteger map(BigInteger value);
}
