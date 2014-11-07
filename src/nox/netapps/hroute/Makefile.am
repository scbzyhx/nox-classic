include ../../../Make.vars 

#SUBDIRS = t

EXTRA_DIST =\
	meta.json\
	__init__.py\
    pyhroute.py\
    routetable.py\
    table.json

NOX_RUNTIMEFILES = meta.json	\
	__init__.py		\
    pyhroute.py     \
    routetable.py   \
    table.json

all-local: nox-all-local
install-exec-hook: nox-install-local
