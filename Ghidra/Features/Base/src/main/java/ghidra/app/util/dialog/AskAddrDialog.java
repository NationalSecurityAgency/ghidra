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
package ghidra.app.util.dialog;

import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

import java.awt.BorderLayout;
import java.lang.reflect.InvocationTargetException;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;


public class AskAddrDialog extends DialogComponentProvider {
    private boolean isCanceled;
    private JLabel label;
    private AddressInput addrInput;

    public AskAddrDialog(final String title, final String message, AddressFactory af, Address lastAddr) {
        super(title, true, true, true, false);

        label = new JLabel(message);

        addrInput = new AddressInput();
        addrInput.setAddressFactory(af);
        addrInput.selectDefaultAddressSpace();
        if (lastAddr != null) {
            addrInput.setAddress(lastAddr);
        }
        addrInput.select();

        JPanel panel = new JPanel(new BorderLayout(10,10));
        panel.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
        panel.add(label, BorderLayout.WEST);
        panel.add(addrInput, BorderLayout.CENTER);

        addWorkPanel(panel);
        addOKButton();
        addCancelButton();
        setDefaultButton(okButton);

        if (SwingUtilities.isEventDispatchThread()) {
            DockingWindowManager.showDialog(null, this);
        }
        else {
	        try {
				SwingUtilities.invokeAndWait(new Runnable(){
					public void run() {
				        DockingWindowManager.showDialog(null, AskAddrDialog.this);
					}
				});
			}
	        catch (InterruptedException e) {}
	        catch (InvocationTargetException e) {}
        }
    }

    @Override
    protected void okCallback() {
		isCanceled = false;
		if (addrInput.getAddress() == null) {
		    setStatusText("Please enter a valid ADDRESS.");
		    return;
		}
		close();
	}
	
	@Override
    protected void cancelCallback() {
	    isCanceled = true;
	    close();
	}
	
	public boolean isCanceled() {
	    return isCanceled;
	}
	
	public Address getValueAsAddress() {
	    return addrInput.getAddress();
	}
}
