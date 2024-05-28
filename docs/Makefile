# Minimal Makefile for Sphinx documentation

# Directories
SOURCEDIR     := source
BUILDDIR      := build
DOCDIR        := doc

# Sphinx executable
SPHINXBUILD   ?= sphinx-build

# Optional arguments
SPHINXOPTS    ?=

# Phony targets
.PHONY: help clean html pdf

# Default target
all: html pdf

# Help target
help:
	@$(SPHINXBUILD) -M help $(SOURCEDIR) $(BUILDDIR) $(SPHINXOPTS)

# Clean target
clean:
	$(RM) -rf $(BUILDDIR) $(DOCDIR)

# HTML documentation target
html: $(BUILDDIR)/html

$(BUILDDIR)/html: $(SOURCEDIR)
	$(SPHINXBUILD) -b html $(SOURCIR) $(BUILDDIR) $(SPHINXOPTS)

# PDF documentation target
pdf: $(DOCDIR)/pdf

$(DOCDIR)/pdf: $(SOURCEDIR)
	$(SPHINXBUILD) -b latex $(SOURCEDIR) $(BUILDDIR)
	cd $(BUILDDIR) && make -f Makefile pdf
	mv $(BUILDDIR)/pdf/$(SPHINXBUILD)-build/latex/*.pdf $(DOCDIR)/pdf

