
PANDOC=pandoc

default: all

%.html: %.md
	$(PANDOC) -B navhead.htm --section-divs --toc -c style.css -s --lua-filter=links-to-html.lua --syntax-definition=gdb_syntax.xml --syntax-definition=sleigh_syntax.xml --metadata title="Ghidra Debugger" $< -o $@

all: \
		A1-GettingStarted.html \
		A2-UITour.html \
		A3-Breakpoints.html \
		A4-MachineState.html \
		A5-Navigation.html \
		A6-MemoryMap.html \
		B1-RemoteTargets.html \
		B2-Emulation.html \
		B3-Scripting.html \
		B4-Modeling.html

clean:
	-rm *.html
