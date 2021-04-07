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
package ghidra.dbg.model;

import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public class TestDebuggerModelBuilder {
	public TestDebuggerModelFactory testFactory = new TestDebuggerModelFactory();
	public TestDebuggerObjectModel testModel;

	public TestTargetProcess testProcess1;
	public TestTargetThread testThread1;
	public TestTargetThread testThread2;
	public AbstractTestTargetRegisterBank<?> testBank1;
	public AbstractTestTargetRegisterBank<?> testBank2;

	public TestTargetProcess testProcess3;
	public TestTargetThread testThread3;
	public TestTargetThread testThread4;
	public AbstractTestTargetRegisterBank<?> testBank3;
	public AbstractTestTargetRegisterBank<?> testBank4;

	public TestTargetRegister testRegisterPC;
	public TestTargetRegister testRegisterSP;

	public void createTestModel() {
		createTestModel("Session");
	}

	public void createTestModel(String typeHint) {
		testModel = new TestDebuggerObjectModel(typeHint);
	}

	public Address addr(long offset) {
		return testModel.addr(offset);
	}

	public AddressRange rng(long min, long max) {
		return testModel.range(min, max);
	}

	public void createTestProcessesAndThreads() {
		testProcess1 = testModel.addProcess(1);
		testThread1 = testProcess1.addThread(1);
		testThread2 = testProcess1.addThread(2);

		testProcess3 = testModel.addProcess(3);
		testThread3 = testProcess3.addThread(3);
		testThread4 = testProcess3.addThread(4);
	}

	/**
	 * Create register banks according to a convention.
	 * 
	 * Whatever the convention, it ought to be the same throughout the model, or at least within a
	 * container. This applies the same convention (as defined by -func-) to all test threads.
	 * 
	 * @param func a function which creates one bank for a given thread
	 */
	public void applyThreadRegisterBankConvention(
			Function<TestTargetThread, AbstractTestTargetRegisterBank<?>> func) {
		testBank1 = func.apply(testThread1);
		testBank2 = func.apply(testThread2);
		testBank3 = func.apply(testThread3);
		testBank4 = func.apply(testThread4);
	}

	/**
	 * Create register banks which are direct attributes of the threads.
	 */
	public void createTestThreadRegisterBanks() {
		applyThreadRegisterBankConvention(t -> t.addRegisterBank());
	}

	/**
	 * Create register banks which are the top frame of stacks attributed to the threads.
	 */
	public void createTestThreadStacksAndFramesAreRegisterBanks() {
		applyThreadRegisterBankConvention(t -> t.addStack().pushFrameIsBank(addr(0x00400000)));
	}

	/**
	 * Create register banks which are attributes of the top frame of stacks attributed to the
	 * threads.
	 */
	public void createTestThreadStacksAndFramesHaveRegisterBanks() {
		applyThreadRegisterBankConvention(
			t -> t.addStack().pushFrameHasBank(addr(0x00400000)).getBank());
	}
}
