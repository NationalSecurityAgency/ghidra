package ghidra.app.decompiler.component;

import java.util.ArrayList;

public class HighlightTokenObservableList<T> extends ArrayList<T> {
    private ArrayList<DecompilerPanel> panels = new ArrayList<DecompilerPanel>();

    public HighlightTokenObservableList(DecompilerPanel panel) {
    	super();
    	panels.add(panel);
    }

    public HighlightTokenObservableList() {
    	super();
    }

    @Override
    public boolean add(T t){
    	boolean rslt = super.add(t);
        notifyListeners();
        return rslt;
    }

    @Override
    public void clear() {
    	super.clear();
    	notifyListeners();
    }

    @Override
    public boolean remove(Object t){
        boolean rslt = super.remove(t);
        notifyListeners();
        return rslt;
    }

    public void addListener(DecompilerPanel panel) {
    	this.panels.add(panel);
    }

    public void notifyListeners() {
        if (panels != null) {
	        panels.forEach(p -> {
	        	p.repaintHighlightTokens(true);
		        p.repaint();
	        });
        }
    }
}
