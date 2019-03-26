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
package ghidra.program.model.util;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;

/**
 * 
 */
public class PropertyMapTest extends AbstractGenericTest {
		AddressSpace space = new GenericAddressSpace("MEM", 32, AddressSpace.TYPE_RAM, 0);

    /**
     * Constructor for PropertyMapTest.
     * @param arg0
     */
    public PropertyMapTest() {
        super();
    }

	private Address addr(int i) {
		return space.getAddress(i);
	}
@Test
    public void testIterator() {
		IntPropertyMap map = new DefaultIntPropertyMap("TEST");	
		
		map.add(addr(0),0);
		map.add(addr(100), 100);
		map.add(addr(200), 200);
		map.add(addr(300), 300);
		map.add(addr(400), 400);
		map.add(addr(500), 500);
		map.add(addr(600), 600);
		map.add(addr(700), 700);
		map.add(addr(800), 800);
		map.add(addr(900), 900);
	
		AddressSet as = new AddressSet();
		as.addRange(addr(0), addr(250));
		as.addRange(addr(450), addr(460));
		as.addRange(addr(750), addr(900));	

		Address[] results = {addr(0), addr(100), addr(200),
							 addr(800), addr(900) };
							 
		int i = 0;
		AddressIterator it = map.getPropertyIterator(as);
		while(it.hasNext()) {
			Address addr = it.next();
			Assert.assertEquals(addr, results[i++]);
		}
		Assert.assertEquals(i,5); 
		it = map.getPropertyIterator(as, false);
		while(it.hasNext()) { 
			Address addr = it.next();
			Assert.assertEquals(addr, results[--i]);	
		}
		Assert.assertEquals(0,i);
	}			
}
