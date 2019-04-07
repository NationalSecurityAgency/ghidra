/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.services;

/**
 * Listener interface for BlockModelService.
 */
public interface BlockModelServiceListener {
	
	/**
	 * Provides notification when a model is added.
	 * @param modeName name of the block model that was added
	 * @param modelType type of block model that was added
	 */
	public void modelAdded(String modeName, int modelType);
	
	/**
	 * Provides notifiication when a model is removed.
	 * @param modeName name of the block model that was removed
	 * @param modelType type of block model that was removed
	 */
	public void modelRemoved(String modeName, int modelType);

}
