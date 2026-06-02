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
package db.buffers;

import java.io.IOException;

import ghidra.util.task.TaskMonitor;

public interface BlockStreamHandle<T extends BlockStream> {

	/**
	 * Invoked by client to establish the remote connection and return 
	 * the opened block stream.
	 * @param monitor monitor which will allow cancellation of transfer
	 * @return connected/open block stream
	 * @throws IOException if an IO error occurs
	 */
	public T openBlockStream(TaskMonitor monitor) throws IOException;
	
}
