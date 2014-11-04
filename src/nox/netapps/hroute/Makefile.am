include ../../../Make.vars 

#SUBDIRS = t

EXTRA_DIST =\
	meta.json\
	__init__.py\
    gateway.py

NOX_RUNTIMEFILES = meta.json	\
	__init__.py		\
    gateway.py

all-local: nox-all-local
install-exec-hook: nox-install-local
