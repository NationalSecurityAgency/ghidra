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
package ghidra.app.plugin.core.functiongraph.util.job;

import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.graph.job.GraphJob;
import ghidra.graph.job.GraphJobListener;

/**
 * A dummy job that is designed to simply call the {@link FGController#ungroupAllVertices()}.  
 * We use this job to know when the previous job is finished.
 */
public class UngroupAllVertexFunctionGraphJob implements GraphJob {

	private final FGController controller;
	private boolean isFinished;

	public UngroupAllVertexFunctionGraphJob(FGController controller) {
		this.controller = controller;
	}

	@Override
	public void execute(GraphJobListener listener) {
		try {
			controller.ungroupAllVertices();
		}
		finally {
			isFinished = true;
			listener.jobFinished(this);
		}
	}

	@Override
	public boolean canShortcut() {
		return false;
	}

	@Override
	public void shortcut() {
		throw new UnsupportedOperationException("Cannot shortct job: " + this);
	}

	@Override
	public boolean isFinished() {
		return isFinished;
	}

	@Override
	public void dispose() {
		isFinished = true;
	}

	@Override
	public String toString() {
		return "Ungroup All Group Vertices Job";
	}
}
