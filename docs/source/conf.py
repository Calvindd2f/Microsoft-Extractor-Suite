# Configuration file for the Sphinx documentation builder.

# -- Project information
project = 'Microsoft Extractor Suite'
copyright = '2024, Invictus Incident Response'
author = 'Joey Rentenaar, Korstiaan Stam'

release = '1.3.4'
version = '1.3.4'

# -- General configuration
extensions = [
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
]

# Set the domain for intersphinx to the Python standard library
intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'sphinx': ('https://www.sphinx-doc.org/en/master/', None),
}
intersphinx_disabled_domains = ['std']

# -- Options for HTML output
html_theme = 'sphinx_rtd_theme'

# -- Options for EPUB output
epub_show_urls = 'footnote'

# -- Options for PDF output
pdf_documents = [
    ('Microsoft Extractor Suite Documentation', 'Microsoft_Extractor_Suite.pdf', 'Invictus Incident Response',
     'Copyright 2024 Invictus Incident Response. All rights reserved.', 'manual'),
]

# -- Options for Extended API
autosummary_generate = True
autodoc_member_order = 'bysource'
