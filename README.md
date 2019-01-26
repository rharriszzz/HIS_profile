Make sure "Hardware Instrumentation Services" is enabled on your LPAR.


Install "his_profile"
conda install -c ODSP-TEST/label/performance his_profile

APF authorize the program that issues operator commands.
extattr +a $CONDA_PREFIX/bin/issue_command
Use chmod to restrict who can run this command, unless you trust all the users of your lpar

Use this statement to import the functions that you will need:
from his_profile import run_test, print_tree

run_test takes two arguments,
  a string that names the test (which is supposed to be used in building fome of the filenames)
  and a function of 0 arguments that runs the test,
  and optionally a log argument, that defaults to sys.stdout
and it returns a string that is the name of results file (which is pickled)

print_tree takes one argument,
  the name of a results file (or the results tree itself),
  and optionally a threshold, which defaults to 0.0025
and it prints the results tree



To show the results in a jupyter notebook using bokeh:

conda create --name py37 --channel ODSP-TEST/label/ptf_2019_q1 python=3.7.0 bokeh jupyter notebook terminado tornado
conda activate py37

Create a jupyter notebook:

from bokeh.io import output_notebook, show
from bokeh.resources import Resources
output_notebook()

from his_profile import show_tree

with open('pyan_38_1_test.log', "wt") as log:
    tree_filename = run_test('scipy_odeint_grayscott1d_non-banded', pyan_38_1_test)
show_tree(not_chunked_tree_filename)

Note: This notebook is notebook/Tree.ipynb in the his_profile git repo at git@github.ibm.com:zGollum/his_profile.git

