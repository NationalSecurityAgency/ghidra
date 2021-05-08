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
package ghidra.app.plugin.core.stackeditor;

import static org.junit.Assert.*;

import javax.swing.JTextField;

import org.junit.Before;
import org.junit.Test;

import ghidra.framework.model.*;
import ghidra.program.model.data.DataTypeManagerDomainObject;
import ghidra.program.model.data.Pointer;

public class PositiveStackEditorProviderTest extends AbstractStackEditorTest {

	public PositiveStackEditorProviderTest() {
		super(true);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	@Test
	public void testIncreasePosLocalSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField localSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Local Size", true);
		setField(localSizeField, "0x16");
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
	}

	@Test
	public void testDecreasePosLocalSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField localSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Local Size", true);
		setField(localSizeField, "0xc");
		assertEquals(0x16, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0xc, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		assertEquals(0xf, stackModel.getNumComponents());
		assertTrue(getDataType(14) instanceof Pointer);
	}

	@Test
	public void testIncreasePosParamSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField paramSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Parameter Size", true);
		setField(paramSizeField, "0xe");
		assertEquals(0x24, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xe, stackModel.getParameterSize());
	}

	@Test
	public void testDecreasePosParamSize() throws Exception {
		init(SIMPLE_STACK);
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());
		JTextField paramSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Parameter Size", true);
		setField(paramSizeField, "0x4");
		assertEquals(0x1a, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x16, stackModel.getLocalSize());
		assertEquals(-0x4, stackModel.getParameterOffset());
		assertEquals(0x4, stackModel.getParameterSize());
	}

//	public void testIncreasePosReturnAddrOffset() throws Exception {
//		init(SIMPLE_STACK);
//		assertEquals(0x20, stackModel.getFrameSize());
//		assertEquals(0x0, stackModel.getReturnAddressOffset());
//		assertEquals(0x12, stackModel.getLocalSize());
//		assertEquals(-0x8, stackModel.getParameterOffset());
//		assertEquals(0x7, stackModel.getParameterSize());
//	}
//
//	public void testDecreasePosReturnAddrOffset() throws Exception {
//		init(SIMPLE_STACK);
//		assertEquals(0x20, stackModel.getFrameSize());
//		assertEquals(0x0, stackModel.getReturnAddressOffset());
//		assertEquals(0x12, stackModel.getLocalSize());
//		assertEquals(-0x8, stackModel.getParameterOffset());
//		assertEquals(0x7, stackModel.getParameterSize());
//	}

	protected class RestoreListener implements DomainObjectListener {
		/**
		 * @see ghidra.framework.model.DomainObjectListener#domainObjectChanged(ghidra.framework.model.DomainObjectChangedEvent)
		 */
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent event) {
			if (event.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
				Object source = event.getSource();
				if (source instanceof DataTypeManagerDomainObject) {
					DataTypeManagerDomainObject restoredDomainObject =
						(DataTypeManagerDomainObject) source;
					provider.domainObjectRestored(restoredDomainObject);
				}
			}
		}
	}

}
