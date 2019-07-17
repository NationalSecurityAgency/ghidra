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
package ghidra.app.plugin.core.overview.entropy;

/**
 * Enum for the various supported entropy chunk sizes.
 */
public enum EntropyChunkSize {
	SMALL("256 Bytes", 256), MEDIUM("512 Bytes", 512), LARGE("1024 Bytes", 1024);

	private String label;
	private int chunksize;

	private EntropyChunkSize(String label, int csize) {
		this.label = label;
		this.chunksize = csize;
	}

	@Override
	public String toString() {
		return label;
	}

	public int getChunkSize() {
		return chunksize;
	}

}
