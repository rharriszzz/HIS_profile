# (c) Copyright Rocket Software, Inc. 2018, 2019 All Rights Reserved.

from numpy import pi
from bokeh.colors import HSL
from bokeh.plotting import *
from bokeh.models import HoverTool
from .his_profile import tree_item_count
from math import fmod
import pickle

def invert_data(list_of_dicts):
    result = dict()
    for d in list_of_dicts:
        for name, value in d.items():
            if name not in result:
                result[name] = list()
            result[name].append(value)
    return result

def color_for_wedge(level, total, subtotal_for_color):
    return HSL(int(256*0.99999*(subtotal_for_color/total)),
               1.0, # 1.0 - subtree.count/float(tree.count), # sat [0,1]
               0.5, # 0.4+(level*0.2)/6, # light [0=black,1/2=sat,1=white]
               1.0) # alpha

def tree_to_wedge_data(data, tree, level=0, total=None, subtotal=0, ancestor_subtotal=None,
                       threshold = 0.0025):
    if total is None:
        total = float(tree.count)
    initial_subtotal = subtotal
    final_subtotal = subtotal + tree.count
    item_list = tree.key_to_subtree.items()
    subtotal_for_color = initial_subtotal if level == 0 else ancestor_subtotal
    for key, subtree in sorted(item_list, key=tree_item_count, reverse=True):
        if subtree.count/total <= threshold:
            break
        subtotal_begin = subtotal
        subtotal_end = subtotal + subtree.count
        if level == 0:
            subtotal_for_color = subtotal_begin
        elif (subtotal_end-subtotal_begin)/(final_subtotal-initial_subtotal) >= 0.66:
            subtotal_for_color = ancestor_subtotal
        else:
            subtotal_for_color = fmod(subtotal_for_color+0.1*total, total)
        data.append({'inner_radius':level, 'outer_radius':level+1,
                         'start_angle':(subtotal/total)*2*pi, 'end_angle':(subtotal_end/total)*2*pi,
                         'fill_color':color_for_wedge(level, total, subtotal_for_color),
                         'name':key})
        tree_to_wedge_data(data, subtree, level=level+1,
                           total=total, subtotal=subtotal, ancestor_subtotal=subtotal_for_color, threshold=threshold)
        subtotal += subtree.count
        ancestor_subtotal = None
    if False:                
        data.append({'inner_radius':level, 'outer_radius':level+1,
                         'start_angle':(subtotal/total)*2*pi, 'end_angle':(final_subtotal/total)*2*pi,
                         'fill_color':HSL(0,1,1),
                         'name':'(other)'})

def show_tree(pickled_tree):
    with open(pickled_tree, "rb") as tree_pickle_file:
        tree = pickle.load(tree_pickle_file)
    data = []
    tree_to_wedge_data(data, tree)
    source = ColumnDataSource(invert_data(data))
    p = figure(x_range=(-8, 8), y_range=(-8, 8))
    circle_x, circle_y = (0, 0)
    p.annular_wedge(circle_x, circle_y,
                    inner_radius='inner_radius', outer_radius='outer_radius',
                    start_angle='start_angle', end_angle='end_angle',
                    fill_color='fill_color', name='name',
                    source=source)
    p.add_tools(HoverTool(tooltips="@name", show_arrow=False, point_policy='follow_mouse'))
    show(p)

def show_example_tree():
    show_tree('/u/pdharr/profile_tree_2018-02-27-13:53:03.pkl')
    
