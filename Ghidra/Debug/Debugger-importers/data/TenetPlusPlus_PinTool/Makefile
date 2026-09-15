CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

TOOL_ROOTS := tenetplusplus

$(OBJDIR)tenetplusplus$(PINTOOL_SUFFIX): $(OBJDIR)tenetplusplus$(OBJ_SUFFIX)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $^ $(TOOL_LPATHS) $(TOOL_LIBS)

include $(TOOLS_ROOT)/Config/makefile.default.rules

all: $(OBJDIR)tenetplusplus$(PINTOOL_SUFFIX)