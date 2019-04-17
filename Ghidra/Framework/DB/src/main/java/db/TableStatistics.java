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
package db;

/**
 * Table statistics data
 */
public class TableStatistics {
	
	/**
	 * Name of table (same name used by both primary table and related index tables)
	 */
	public String	name;
	
	/**
	 * For index tables, this indicates the indexed column within the primary table.
	 * For primary tables, this value is -1 and does not apply.
	 */
	public int	indexColumn = -1;
	
	/**
	 * Total number of table nodes
	 */
	public int	bufferCount;
	
	/**
	 * Total size of table
	 */
	public int	size;
	
	/**
	 * Total number of interior nodes
	 */
	public int	interiorNodeCnt;
	
	/**
	 * Total number of leaf/record nodes.
	 */
	public int	recordNodeCnt;
	
	/**
	 * Total number of buffers used within chanined DBBuffers for
	 * record storage.
	 */
	public int	chainedBufferCnt;
}
