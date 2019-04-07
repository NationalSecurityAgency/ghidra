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
package ghidra.graph.viewer;

/**
 * A listener to get notified of changes to the {@link SatelliteGraphViewer}
 */
public interface GraphSatelliteListener {

	/**
	 * Called when the visibility and/or docked state of the watched satellite changes
	 * 
	 * @param docked true if the satellite is now docked
	 * @param visible true if the satellite is now visible
	 */
	public void satelliteVisibilityChanged(boolean docked, boolean visible);
}
